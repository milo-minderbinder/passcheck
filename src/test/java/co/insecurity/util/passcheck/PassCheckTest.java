package co.insecurity.util.passcheck;

import org.junit.Assert;
import org.junit.Test;

public class PassCheckTest {

	@Test
	public void defaultShouldContainPassword() {
		PassCheck pc = new PassCheck();
		Assert.assertTrue("Failed - default PassCheck should contain 'password'", pc.isCommon("password"));
	}
}
