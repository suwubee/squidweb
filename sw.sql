CREATE DATABASE IF NOT EXISTS `squidweb`;
CREATE TABLE IF NOT EXISTS `squidweb`.`accesslog` (
  id INTEGER(10) UNSIGNED AUTO_INCREMENT,
  acessed_at DATETIME NOT NULL,
  url VARCHAR(1000) NOT NULL,
  user_id INTEGER(4) NOT NULL,
  blocked BOOLEAN NOT NULL,
  PRIMARY KEY (id)
);
