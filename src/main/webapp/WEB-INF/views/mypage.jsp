<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
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
			<p>아이디 : ${id }</p>
			<p>권한 : </p>
			<ul>
				<c:forEach var="role" items="${roles }">
					<li>${role.authority }</li>
				</c:forEach>
			</ul>
			<p>
				<a href="/">메인 화면</a>
			</p>
		</div>
	</div>
</body>
</html>