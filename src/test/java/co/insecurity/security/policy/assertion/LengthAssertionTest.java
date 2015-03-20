package co.insecurity.security.policy.assertion;


import org.junit.Assert;
import org.junit.Test;

public class LengthAssertionTest {

	@Test
	public void thatNullFailsLengthAssertion() {
		LengthAssertion lengthPA = new LengthAssertion();
		Assert.assertFalse("Failure - null string should fail length assertion", 
				lengthPA.isTrueFor(null));
		lengthPA = new LengthAssertion(8, 128);
		Assert.assertFalse("Failure - null string should fail length assertion", 
				lengthPA.isTrueFor(null));
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
				lengthPA.isTrueFor(""));
		Assert.assertTrue("Failure - there should be no default minLength", 
				lengthPA.isTrueFor("a"));
	}
	
	@Test
	public void thatNoDefaultMaxLength() {
		LengthAssertion lengthPA = new LengthAssertion();
		Assert.assertTrue("Failure - there should be no default minLength", 
				lengthPA.isTrueFor("e;lkjzsdfboaisjrpoqiuf-09f7db9078a60f8a7sdfuio"
						+ "h40iauysdf07a6sdfjhegfkjahdfljkhel;kajsdfalsdkfja;s"
						+ "dklfja;sdlkjelkasjdf;lkj4p;kljfc8b8703986738976gasd"
						+ "ralsdkjhlbkul;kaserj;jkhdkajsd;flkjwe;rkljasd;flkja"
						+ "sd;glkh4h4h4jjdfgk"));
	}
	
	@Test
	public void thatMinLengthEnforced() {
		LengthAssertion lengthPA = new LengthAssertion(0, LengthAssertion.DISABLED);
		Assert.assertTrue("Failure - minLength should be enforced", 
				lengthPA.isTrueFor(""));
		lengthPA = new LengthAssertion(1, LengthAssertion.DISABLED);
		Assert.assertFalse("Failure - minLength should be enforced", 
				lengthPA.isTrueFor(""));
		lengthPA = new LengthAssertion(1, LengthAssertion.DISABLED);
		Assert.assertTrue("Failure - minLength should be enforced", 
				lengthPA.isTrueFor("a"));
		lengthPA = new LengthAssertion(8, LengthAssertion.DISABLED);
		Assert.assertTrue("Failure - minLength should be enforced", 
				lengthPA.isTrueFor("password"));
	}
	
	@Test
	public void thatMaxLengthEnforced() {
		LengthAssertion lengthPA = new LengthAssertion(LengthAssertion.DISABLED, 0);
		Assert.assertTrue("Failure - maxLength should be enforced", 
				lengthPA.isTrueFor(""));
		lengthPA = new LengthAssertion(LengthAssertion.DISABLED, 0);
		Assert.assertFalse("Failure - maxLength should be enforced", 
				lengthPA.isTrueFor("a"));
		lengthPA = new LengthAssertion(LengthAssertion.DISABLED, 8);
		Assert.assertTrue("Failure - maxLength should be enforced", 
				lengthPA.isTrueFor("a"));
		lengthPA = new LengthAssertion(LengthAssertion.DISABLED, 8);
		Assert.assertTrue("Failure - maxLength should be enforced", 
				lengthPA.isTrueFor("password"));
	}
}