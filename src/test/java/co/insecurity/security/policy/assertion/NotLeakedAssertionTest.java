package co.insecurity.security.policy.assertion;

import java.io.IOException;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class NotLeakedAssertionTest {
	
	private static NotLeakedAssertion notLeakedPA;
	
	@BeforeClass
	public static void setUpClass() throws IOException {
		notLeakedPA = new NotLeakedAssertion.Builder().build();
	}
	
	@AfterClass
	public static void tearDownClass() {
		notLeakedPA = null;
	}

	@Test
	public void thatDefaultsAreSet() {
		Assert.assertEquals(
				"Failure - default false positive probability should be 0.001",
				0.001,
				notLeakedPA.getFalsePositiveProbability(),
				0.0);
		Assert.assertEquals(
				"Failure - default maxNumPasswords should be NotLeakedAssertion.DISABLED",
				NotLeakedAssertion.MAX_NUM_PASSWORDS_DISABLED,
				notLeakedPA.getMaxNumPasswords());
		Assert.assertNull(
				"Failure - default password data file should be null",
				notLeakedPA.getPasswordDataFile());
		Assert.assertFalse(
				"Failure - default should not ignore case",
				notLeakedPA.getIgnoreCase());
		Assert.assertTrue(
				"Failure - default should have passwords loaded into the filter",
				(notLeakedPA.getNumPasswords() > 0));
	}
	
	@Test
	public void thatNullFailsDefaultNotLeakedAssertion() {
		Assert.assertFalse(
				"Failure - null value should fail policy assertion",
				notLeakedPA.isTrueFor(null));
	}

	@Test
	public void thatPasswordFailsDefaultNotLeakedAssertion() {
		Assert.assertFalse(
				"Failure - default word list should contain 'password'",
				notLeakedPA.isTrueFor("password"));
	}
	
	@Test
	public void thatCustomPasswordDataFileFunctions() throws IOException {
		NotLeakedAssertion customDataAssertion = new NotLeakedAssertion
				.Builder().withFalsePositiveProbability(0.001)
				.withMaxNumPasswords(2)
				.withIgnoreCase(true)
				.withPasswordDataFile("src\\test\\"
						+ "resources\\testpasswords.dat")
				.build();
		Assert.assertEquals(
				"Failure - false positive probability should be 0.001",
				0.001,
				customDataAssertion.getFalsePositiveProbability(),
				0.0);
		Assert.assertEquals(
				"Failure - maxNumPasswords should be NotLeakedAssertion.DISABLED",
				2,
				customDataAssertion.getMaxNumPasswords());
		Assert.assertNotNull(
				"Failure - password data file should not be null",
				customDataAssertion.getPasswordDataFile());
		Assert.assertTrue(
				"Failure - case should be ignored",
				customDataAssertion.getIgnoreCase());
		Assert.assertTrue(
				"Failure - should have 2 passwords loaded into the filter",
				(customDataAssertion.getNumPasswords() == 2));
		Assert.assertFalse(
				"Failure - filter should contain 'password'",
				customDataAssertion.isTrueFor("password"));
		Assert.assertFalse(
				"Failure - filter should contain 'dog'",
				customDataAssertion.isTrueFor("dog"));
		Assert.assertFalse(
				"Failure - filter should contain 'PASSWORD'",
				customDataAssertion.isTrueFor("PASSWORD"));
		Assert.assertTrue(
				"Failure - filter should not contain 'i should be ignored'",
				customDataAssertion.isTrueFor("i should be ignored"));
		Assert.assertTrue(
				"Failure - filter should not contain 'cat'",
				customDataAssertion.isTrueFor("cat"));

	}
}