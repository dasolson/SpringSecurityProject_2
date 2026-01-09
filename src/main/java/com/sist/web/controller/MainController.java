package com.sist.web.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.sist.web.mapper.*;
import com.sist.web.vo.*;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class MainController {
	private final PasswordEncoder pEncoder;
	private final UsersMapper mapper;
	
	@GetMapping("/")
	public String main_page() {
		return "main";
	}
	
	@GetMapping("/join")
	public String join_page() {
		return "join";
	}
	
	@PostMapping("/join")
	public String join_ok_page(@ModelAttribute("vo") UsersVO vo) {
		vo.setPassword(pEncoder.encode(vo.getPassword()));
		// pwd.match()
		mapper.usersInsert(vo);
		UsersVO dbVO = mapper.findByUsername(vo.getUsername());
		
		UserRolesVO rvo = new UserRolesVO();
		rvo.setUser_id(dbVO.getId());
		rvo.setRole_name("ROLE_USER");
		mapper.userRolesInsert(rvo);
		
		return "redirect:/";
	}
	
	@GetMapping("/login")
	public String login_page() {
		return "login";
	}
	
	@GetMapping("/all")
	public String all_page() {
		return "all";
	}
	
	@GetMapping("/admin")
	public String admin_page() {
		return "adminpage";
	}
	
	@GetMapping("/user")
	public String user_page(@AuthenticationPrincipal UserDetails userDetail, Model model) {
		model.addAttribute("id", userDetail.getUsername());
		model.addAttribute("roles", userDetail.getAuthorities());
		return "mypage";
	}
}


