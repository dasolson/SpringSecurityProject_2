package com.sist.web.vo;

import lombok.Data;

/*
 * ID        NOT NULL NUMBER       
	USER_ID   NOT NULL NUMBER       
	ROLE_NAME NOT NULL VARCHAR2(50) 
 */
@Data
public class UserRolesVO {
	private int id, user_id;
	private String role_name;
}
