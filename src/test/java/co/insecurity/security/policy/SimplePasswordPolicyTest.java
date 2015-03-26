package co.insecurity.security.policy;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import co.insecurity.security.policy.assertion.LengthAssertion;
import co.insecurity.security.policy.assertion.NotLeakedAssertion;
import co.insecurity.security.policy.assertion.PolicyAssertion;
import co.insecurity.security.policy.assertion.PolicyAssertion.Result;

class SimplePasswordPolicy extends PasswordPolicy {
	
	private static final Logger LOG = 
			LoggerFactory.getLogger(SimplePasswordPolicy.class);

	public SimplePasswordPolicy() {
		assertions = new LinkedHashSet<PolicyAssertion>();
		LengthAssertion length = new LengthAssertion(8, LengthAssertion.DISABLED);
		assertions.add(length);
		try {
			assertions.add(new NotLeakedAssertion
					.Builder().withFalsePositiveProbability(0.001)
					.withIgnoreCase(true)
					.build());
		} catch (IOException e) {
			LOG.error("Failed to build NotLeakedAssertion: ", e);
		}
	}
}
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
		Map<PolicyAssertion, Result> results = policy.evaluate("password");
		Assert.assertNotNull("Failure - results should not be null",
				results);
		Assert.assertTrue("Failure - result should contain results",
				(results.size() > 0));
		Map<PolicyAssertion, Result> violations = 
				PasswordPolicy.getViolations(results); 
		Assert.assertNotNull("Failure - violations should not be null",
				violations);
		Assert.assertTrue("Failure - result should contain one violation",
				(violations.size() == 1));
		Assert.assertTrue("Failure - violations should include LEAKED_PASSWORD",
				violations.containsValue(NotLeakedAssertion.LEAKED_PASSWORD));
	}
	
	@Test
	public void thatSevenCharacterPasswordFailsPolicy() {
		String password = "98V*-++";
		Map<PolicyAssertion, Result> results = policy.evaluate(password);
		Map<PolicyAssertion, Result> violations = 
				PasswordPolicy.getViolations(results);
		Assert.assertTrue("Failure - result should contain one violation",
				(violations.size() == 1));
		Assert.assertTrue(
				"Failure - password should fail minimum length assertion", 
				violations.containsValue(LengthAssertion.INSUFFICIENT_LENGTH));
	}
}