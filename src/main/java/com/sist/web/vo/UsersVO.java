package com.sist.web.vo;

import lombok.Data;

/*
 * 	ID       NOT NULL NUMBER        
	USERNAME NOT NULL VARCHAR2(50)  
	PASSWORD NOT NULL VARCHAR2(300) 
	ENABLED           NUMBER(1) 
 */
@Data
public class UsersVO {
	private int id, enabled;
	private String username, password;
}
