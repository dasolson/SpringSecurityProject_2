<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
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
			<h3 class="text-center">메인 페이지</h3>
			<table class="table">
				<tbody>
					<sec:authorize access="isAnonymous()">
						<tr>
							<td class="text-center">
								<a href="/login" class="btn btn-sm btn-info">로그인</a>
							</td>
							<td class="text-center">
								<a href="/join" class="btn btn-sm btn-success">회원가입</a>
							</td>
						</tr>
					</sec:authorize>
					<%--
								isAuthenticated() ${sessionScope.id != null}
					 --%>
					<sec:authorize access="isAuthenticated()">
						<tr>
							<td colspan="2" class="text-center">
								<strong>
									<sec:authentication property="name"/>
								</strong>&nbsp;환영합니다
							</td>
						</tr>
						<%--
									${sessionScope.admin == 'n'}
						 --%>
						<sec:authorize access="hasRole('USER')">
							<tr>
								<td colspan="2" class="text-center">
									<a href="/user" class="btn btn-sm btn-primary">마이페이지</a>
								</td>
							</tr>
						</sec:authorize>
						<%--
									${sessionScope.admin == 'y'}
						 --%>
						<sec:authorize access="hasRole('ADMIN')">
							<tr>
								<td colspan="2" class="text-center">
									<a href="/admin" class="btn btn-sm btn-primary">관리자페이지</a>
								</td>
							</tr>
						</sec:authorize>
						<tr>
							<td colspan="2" class="text-center">
								<form  method="post" action="/logout">
									<button type="submit">로그아웃</button>
								</form>
							</td>
						</tr>
					</sec:authorize>
					<tr>
						<td colspan="2" class="text-center">
							<a href="/all" class="btn btn-sm btn-primary">모든 사용자</a>
						</td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>
</body>
</html>