package co.insecurity.security.policy;


import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Assert;
import org.junit.Test;

public class SimplePasswordPolicyTest {

	private static SimplePasswordPolicy policy;
	
	@BeforeClass
	public static void setUpClass() {
		policy = new SimplePasswordPolicy();
	}
	
	@AfterClass
	public static void tearDownClass() {
		policy = null;
	}
	
	@Test
	public void thatPasswordFailsPolicy() {
		Assert.assertFalse("Failure - 'password' should fail the policy",
				policy.checkCompliance("password"));
	}
	
	@Test
	public void thatSevenCharacterPasswordFailsPolicy() {
		Assert.assertFalse("Failure - '98V*-++' should fail the policy",
				policy.checkCompliance("98V*-++"));
	}
}