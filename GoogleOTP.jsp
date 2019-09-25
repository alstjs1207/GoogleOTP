<html>
<head>
<title>GoogleOTP</title>
<script type="text/javascript">

function login()
{
		var otp = document.getElementById("otp").value; //인증코드
		var id = document.getElementById("id").value; // 계정

		jQuery.ajax({
			type: 'get'
			, url : '/GoogleOTP/cert'
			, data : {"id" : id, "otp" : otp}
			, dataType : "json"
			, contentType: "application/json"
			, success:function(json) {
			if (json.result) {
				alert("인증 성공하였습니다.");
			} else {
			alert("인증에 실패하였습니다.");
			}
			    }
			   , error:function(xhr,textStatus){
			   alert("인증 장애가 발생되었습니다.\n 다시 시도해주세요.");
			    }
			});
	}
	
function cretOTP()
{	
	var id = document.getElementById("id").value;
	var email = document.getElementById("email").value;
	
	jQuery.ajax({
		type :'GET'
		, url : '/GoogleOTP/generateOTP'
		, data : {"id": id, "email": email}
		, dataType : "json"
		, contentType: "application/json"
		, success:function(json) {
			if (json.result == 'true') {
				alert("OTP가 발급 완료되었습니다.");
				alert(json.otpkey);
				alert(json.url);
			} else {
				alert("OTP발급에 실패하였습니다.");
			}
	    }
			, error:function(xhr,textStatus){
				alert("OTP발급 중 장애가 발생되었습니다. 다시 시도해주세요.");
		}
	});
}

</script>

</head>
<body>
<div>
	<ul>
		<li><input type="button" onclick="cretOTP()"  id="otp" alt="OTP등록" /></li>
		<li><input type="button" id="login"onclick="login()"alt="로그인" /></li>
	</ul>
</div>
</body>
</html>
