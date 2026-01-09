package com.sist.web.mapper;
import java.util.List;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import com.sist.web.vo.*;
/*
 * 		user / admin
 *               | ROLE_ADMIN, ROLE_USER
 *        | ROLE_USER       
 */
@Mapper
@Repository
public interface UsersMapper {
	@Insert("INSERT INTO users(username, password) VALUES(#{username}, #{password})")
	public void usersInsert(UsersVO vo);
	
	@Insert("INSERT INTO user_roles(user_id, role_name) "
			+ "VALUES(#{user_id}, #{role_name})")
	public void userRolesInsert(UserRolesVO vo);
	
	@Select("SELECT * FROM users WHERE username=#{username}")
	public UsersVO findByUsername(String username);
	
	@Select("SELECT role_name FROM user_roles WHERE user_id=#{userId}")
	public List<String> findRolesByUserId(int userId);
	
	// 로그인 ..
}
