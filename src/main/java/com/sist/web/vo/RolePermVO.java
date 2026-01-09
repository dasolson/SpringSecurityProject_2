package com.sist.web.vo;

import lombok.Data;

/*
 * ID        NOT NULL NUMBER       
	ROLE_NAME NOT NULL VARCHAR2(50) 
	PERM_NAME NOT NULL VARCHAR2(50) 
 */
@Data
public class RolePermVO {
	private int id;
	private String role_name, perm_name;
}
