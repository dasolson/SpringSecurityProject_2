<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
<style type="text/css">
.container {
	margin-top: 50px;
}
.row {
	width: 350px;
	margin: 0px auto;
}
</style>
</head>
<body>
	<div class="container">
		<div class="row">
			<h3 class="text-center">로그인</h3>
			<form  method="post" action="">
				<table class="table">
					<tbody>
						<tr>
							<td width="25%">아이디</td>
							<td width="75%">
								<input type="text" name="username" size="20">
							</td>
						</tr>
						<tr>
							<td width="25%">비밀번호</td>
							<td width="75%">
								<input type="password" name="password" size="20">
							</td>
						</tr>
						<tr>						
							<td colspan="2">
								자동 로그인 : <input type="checkbox" name="remember-me">
							</td>
						</tr>
						<tr>						
							<td colspan="2" class="text-center">
								<button type="submit">로그인</button>
								<button type="button" onclick="javascript:history.back()">취소</button>
							</td>
						</tr>
					</tbody>
				</table>
			</form>
			<c:if test="${param.error != null }">
				<p style="color: red">${sessionScope.loginError }</p>
			</c:if>
		</div>
	</div>			
</body>
</html>