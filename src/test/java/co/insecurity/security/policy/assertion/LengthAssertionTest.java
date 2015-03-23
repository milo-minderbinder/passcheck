package co.insecurity.security.policy.assertion;


import org.junit.Assert;
import org.junit.Test;

public class LengthAssertionTest {

	@Test
	public void thatNullFailsLengthAssertion() {
		LengthAssertion lengthPA = new LengthAssertion();
		Assert.assertEquals("Failure - null string should fail default length assertion",
				PolicyAssertion.Result.NULL_VALUE,
				lengthPA.verify(null));
		lengthPA = new LengthAssertion(8, 128);
		Assert.assertEquals("Failure - null string should fail custom length assertion", 
				PolicyAssertion.Result.NULL_VALUE,
				lengthPA.verify(null));
	}

	@Test
	public void thatDefaultMinAndMaxLengthDisabled() {
		LengthAssertion lengthPA = new LengthAssertion();
		Assert.assertEquals("Failure - minLength should be disabled by default",
				LengthAssertion.DISABLED, lengthPA.getMinLength());
		Assert.assertEquals("Failure - maxLength should be disabled by default",
				LengthAssertion.DISABLED, lengthPA.getMaxLength());
	}
	
	@Test
	public void thatNoDefaultMinLength() {
		LengthAssertion lengthPA = new LengthAssertion();
		Assert.assertTrue("Failure - there should be no default minLength", 
				lengthPA.verify("").isSuccess());
		Assert.assertTrue("Failure - there should be no default minLength", 
				lengthPA.verify("a").isSuccess());
	}
	
	@Test
	public void thatNoDefaultMaxLength() {
		LengthAssertion lengthPA = new LengthAssertion();
		Assert.assertTrue("Failure - there should be no default minLength", 
				lengthPA.verify("e;lkjzsdfboaisjrpoqiuf-09f7db9078a60f8a7sdfuio"
						+ "h40iauysdf07a6sdfjhegfkjahdfljkhel;kajsdfalsdkfja;s"
						+ "dklfja;sdlkjelkasjdf;lkj4p;kljfc8b8703986738976gasd"
						+ "ralsdkjhlbkul;kaserj;jkhdkajsd;flkjwe;rkljasd;flkja"
						+ "sd;glkh4h4h4jjdfgk").isSuccess());
	}
	
	@Test
	public void thatMinLengthEnforced() {
		LengthAssertion lengthPA = new LengthAssertion(0, LengthAssertion.DISABLED);
		Assert.assertTrue("Failure - should pass: 0 <= '' <= -1", 
				lengthPA.verify("").isSuccess());

		lengthPA = new LengthAssertion(1, LengthAssertion.DISABLED);
		Assert.assertFalse("Failure - should fail: 1 <= '' <= -1", 
				lengthPA.verify("").isSuccess());

		lengthPA = new LengthAssertion(1, LengthAssertion.DISABLED);
		Assert.assertTrue("Failure - should pass: 1 <= 'a' <= -1", 
				lengthPA.verify("a").isSuccess());

		lengthPA = new LengthAssertion(8, LengthAssertion.DISABLED);
		Assert.assertTrue("Failure - should pass: 8 <= 'password' <= -1", 
				lengthPA.verify("password").isSuccess());
	}
	
	@Test
	public void thatMaxLengthEnforced() {
		LengthAssertion lengthPA = new LengthAssertion(LengthAssertion.DISABLED, 0);
		Assert.assertTrue("Failure - should pass: -1 <= '' <= 0", 
				lengthPA.verify("").isSuccess());
		
		lengthPA = new LengthAssertion(LengthAssertion.DISABLED, 0);
		Assert.assertFalse("Failure - should fail: -1 <= 'a' <= 0", 
				lengthPA.verify("a").isSuccess());
		
		lengthPA = new LengthAssertion(LengthAssertion.DISABLED, 8);
		Assert.assertTrue("Failure - should pass: -1 <= 'a' <= 8", 
				lengthPA.verify("a").isSuccess());
		
		lengthPA = new LengthAssertion(LengthAssertion.DISABLED, 8);
		Assert.assertTrue("Failure - should pass: -1 <= 'password' <= 8", 
				lengthPA.verify("password").isSuccess());
	}
}