#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <mysql.h>

#include "hiredis.h"
#include "iniparser.h"

#define INIFILE "/etc/squid/squidweb.ini"

typedef struct request {
  char line[8000];
  char url[8000];
  char domain[8000];
  char ip[15];
  char reply[8000];
} Request;

char time_return[20];

char * timenow(){

  time_t rawtime;
  struct tm * timeinfo;
  
  // This function returns the current datetime stamp
  // Ex. 2009-03-23 22:32:12 
  time(&rawtime);
  timeinfo=localtime(&rawtime);

  strftime(time_return,20,"%Y-%m-%d %H:%M:%S",timeinfo);

  return time_return;

}

void url_cut(char * url, char * domain){

  // Cut http[s]|ftp:// 
  if((strncmp(url,"http://",7) == 0))
    strcpy(domain,url+7);

  else if((strncmp(url,"https://",8) == 0))
    strcpy(domain,url+8);

  else if((strncmp(url,"ftp://",6) == 0))
    strcpy(domain,url+6);

  // Cut domain.com/\* 
  strtok(domain,"/");

}

void filter(Request * r){
  
  sscanf(r->line, "%1024s %256s", r->url, r->ip);

  url_cut(r->url, r->domain);
  strtok(r->ip,"/");
  
}

int main(int argc, char * argv[]){

  // Make standard output line buffered 
  if(setvbuf(stdout, NULL, _IOLBF, 0)!=0){
    fprintf(stderr, "Sorry unable to configure stdout buffer\n");
    exit(1);
  }

  // Load ini file 
  dictionary * ini = iniparser_load(INIFILE);
  if (ini==NULL) {
    fprintf(stderr, "Cannot parse file: %s\n", INIFILE);
    exit(1);
  }

  // Redirect standart output error to log_error 
  char * log_error = iniparser_getstring(ini, "log:error", "sw-error.log"); 

  if(freopen(log_error, "a", stderr)==NULL){
    printf("Error could not open or create a log file (%s).\n", log_error);
    exit(1);
  }

  // Mysql parameters 
  MYSQL *conn;
  conn = mysql_init(NULL);
  char sql[500];
 
  char * mysql_hostname = iniparser_getstring(ini, "mysql:hostname", "localhost");
  char * mysql_username = iniparser_getstring(ini, "mysql:username", "root");
  char * mysql_password = iniparser_getstring(ini, "mysql:password", NULL);
  char * mysql_database = iniparser_getstring(ini, "mysql:database", "squidweb");
 
  // Open Mysql connection 
  if (!mysql_real_connect(conn, mysql_hostname, mysql_username, mysql_password, mysql_database, 0, NULL, 0)) {
      fprintf(stderr, "%s Mysql connection error (PID %d):  %s\n", timenow(), getpid(), mysql_error(conn));
      exit(1);
   }

  // Redis parameters
  redisContext *c;
  redisReply *user;
  redisReply *reply;

  char * redis_hostname = iniparser_getstring(ini, "redis:hostname", "localhost");
  int redis_port = iniparser_getint(ini, "redis:port", 6379);

  // Open a Redis connection 
  struct timeval timeout={1,500000}; // 1.5 seconds
  c=redisConnectWithTimeout(redis_hostname, redis_port, timeout);
  if (c->err) {
    fprintf(stderr, "%s Redis connection error (PID %d): %s\n", timenow(), getpid(), c->errstr);
    exit(1);
  }

  // Rails parameters 
  char * rails_hostname = iniparser_getstring(ini, "rails:hostname", "localhost");
  int rails_port = iniparser_getint(ini, "rails:port", 3000);
  
  char rails_usernotfound[100];
  char rails_accessdenied[100];

  sprintf(rails_usernotfound, "http://%s:%d/usernotfound", rails_hostname, rails_port);
  sprintf(rails_accessdenied, "http://%s:%d/denied", rails_hostname, rails_port);

  // Ready to parse requests 
  Request r;

  while(fgets(r.line, sizeof(r.line), stdin)!=NULL){
    filter(&r);

    user=redisCommand(c, "HMGET %s id group restrict", r.ip);
    // user->element[0] = id (integer)
    // user->element[1] = group (integer)
    // user->element[2] = restrict (integer)
     
    if(user->type==REDIS_REPLY_ERROR){
      fprintf(stderr, "%s Redis error: %s\n", timenow(), user->str);
      exit(1);
    }

    else if(user->element[0]->str==NULL) // User not found
      strcpy(r.reply, rails_usernotfound);

    else { // User found

      // Verify if the domain belongs to users group 
      reply=redisCommand(c, "SISMEMBER %s %s", r.domain, user->element[1]->str);

      if(reply->type == REDIS_REPLY_ERROR){
        fprintf(stderr, "%s Redis error: %s\n", timenow(), reply->str);
        exit(1);
      }

      // Allowed access
      else if((reply->integer==0&&(strcmp(user->element[2]->str,"0")==0)) || 
              (reply->integer==1&&(strcmp(user->element[2]->str,"1")==0)) )

        strcpy(r.reply, " ");

      // Unauthorized access 
      else
        strcpy(r.reply, rails_accessdenied);

      // Access logs 
      sprintf(sql, "INSERT INTO accesslogs (acessed_at, url, user_id, blocked) VALUES (NOW(), '%.400s', '%s', '%d')", r.url, user->element[0]->str, strcmp(r.reply," ") ? 1 : 0);
      if (mysql_query(conn, sql)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }

      freeReplyObject(reply);
    }

    freeReplyObject(user);
    fprintf(stdout, "%s\n", r.reply);
    fflush(stdout);
  }

  return 0;

}
