DROP TABLE IF EXISTS users;

CREATE TABLE users(
    id INTEGER primary key NOT NULL ,
    user_name TEXT(100) UNIQUE not null, 
    user_password TEXT(100) not null,
);