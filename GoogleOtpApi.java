package googleOtp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base32;
import org.json.simple.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
@SuppressWarnings({ "rawtypes", "unchecked" })
@Controller
@RequestMapping("/GoogleOTP")
public class ApiOtpController {

	/* 
	 * OTP 인증 확인 API
	 */
	@ResponseBody
	@RequestMapping(value = "cert", method = RequestMethod.GET)
	public JSONObject otpCheck(HttpServletRequest request,
			HttpServletResponse response) throws Exception {

		JSONObject data = new JSONObject();

		try {
			User user = new User();
			String id = (String) request.getParameter("id");
			String otp = (String) request.getParameter("otp");
			
			user.setId(id);
			user = getUserSearch(user); //DB에서 ID로 사용자 정보 검색
			
			String otpKey = user.getOtpid(); //저장되어있는 OTP Key 추출
			
			boolean check = checkCode(otp, otpKey); //OTP Check..
			
			data.put("result", check);
			
			
		} catch (Exception e) {

			data.put("state", "N");
			data.put("rtn_code", "ERR01");
			data.put("message", "인증코드가 맞지 않습니다.");
		}

		return data;
	}
	
	/* 
	 * OTP 생성 페이지 호출
	 */
	@ResponseBody
	@RequestMapping(value = "createOTP", method = RequestMethod.GET)
	public ModelAndView createOTP(HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		ModelAndView mv = new ModelAndView("createOTP"); //createOTP 페이지로 이동
		return mv;
	}
	
	/* 
	 * OTP 생성 API
	 */
	@ResponseBody
	@RequestMapping(value = "generateOTP", method = RequestMethod.GET)
	public JSONObject generateOTP(HttpServletRequest request,
			HttpServletResponse response) throws Exception {

		JSONObject data = new JSONObject();
		User user = new User();
		String id = (String) request.getParameter("id");
		String email = (String) request.getParameter("email");
		String otpkey = "";
		String url = "";
		
		user.setId(id);
		user.setEmail(email);
		
		user = getUserSearch(user); // 사용자 정보 확인
		
		//사용자가 있으면
		if(user != null){
			
			//OTP 생성
			HashMap<String, String> map = generate(email.split("@")[0],email.split("@")[1]);
			otpkey = map.get("encodedKey");
			url = map.get("url");
			user.setOtpid(otpkey);
			
			//사용자 정보에 OTP KEY 저장
			updateUsrOtpKey(user);
			
			data.put("result", "true");
			data.put("otpkey",otpkey);
			data.put("url",url);
		} else{
			data.put("result", "false");
		}
		return data;
	}
	
	
	public HashMap<String, String> generate(String username, String domain) {
		HashMap<String, String> map = new HashMap<String, String>();
		byte[] buffer = new byte[5 + 5 * 5];
		new Random().nextBytes(buffer);
		Base32 codec = new Base32();
		byte[] secretKey = Arrays.copyOf(buffer, 10);
		byte[] bEncodedKey = codec.encode(secretKey);

		String encodedKey = new String(bEncodedKey);
		
		String url = getQRBarcodeURL(username, domain, encodedKey);

		map.put("encodedKey", encodedKey);
		map.put("url", url);
		return map;
	}
	
	/*
	 * OTP URL 생성
	 */
	public static String getQRBarcodeURL(String user, String host, String secret) {
		String format2 = "http://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&chld=H|0";
		return String.format(format2, user, host, secret);
	}
	
	
	public boolean checkCode(String userCode, String otpkey) {
		long otpnum = Integer.parseInt(userCode);
		long wave = new Date().getTime() / 30000; //30초 유효 시간
		boolean result = false;
		try {
			Base32 codec = new Base32();
			byte[] decodedKey = codec.decode(otpkey);
			int window = 3;
			for (int i = -window; i <= window; ++i) {
				long hash = verify_code(decodedKey, wave + i);
				if (hash == otpnum) result = true;
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return result;
	}
	
	private static int verify_code(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
		byte[] data = new byte[8];
		long value = t;
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signKey);
		byte[] hash = mac.doFinal(data);

		int offset = hash[20 - 1] & 0xF;

		long truncatedHash = 0;
		for (int i = 0; i < 4; ++i) {
			truncatedHash <<= 8;
			truncatedHash |= (hash[offset + i] & 0xFF);
		}

		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;

		return (int) truncatedHash;
	}
}
