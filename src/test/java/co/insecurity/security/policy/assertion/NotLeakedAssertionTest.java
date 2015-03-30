package co.insecurity.security.policy.assertion;

import java.io.IOException;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NotLeakedAssertionTest {
	
	private static final Logger LOG = LoggerFactory.getLogger(NotLeakedAssertionTest.class);

	private static NotLeakedAssertion notLeakedPA;
	
	@BeforeClass
	public static void setUpClass() throws IOException {
		//notLeakedPA = new NotLeakedAssertion.Builder().build();
		notLeakedPA = (new NotLeakedAssertion.Builder())
				.withFalsePositiveProbability(0.001)
				.withIgnoreCase(false)
				.withRedis("redis", 6379, "redisTestFilter")
				.build();
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
		PolicyAssertion.Result result = notLeakedPA.verify(null);
		Assert.assertFalse(
				"Failure - null value should fail policy assertion",
				result.isSuccess());
		Assert.assertEquals("Failure - result should be NULL_VALUE", 
				PolicyAssertion.Result.NULL_VALUE,
				result);
	}

	@Test
	public void thatPasswordFailsDefaultNotLeakedAssertion() {
		PolicyAssertion.Result result = notLeakedPA.verify("password");
		Assert.assertFalse(
				"Failure - default word list should contain 'password'",
				result.isSuccess());
		Assert.assertEquals("Failure - result should be LEAKED_PASSWORD", 
				NotLeakedAssertion.LEAKED_PASSWORD,
				result);
	}
	
	@Test
	public void thatRedisBackedFilterFunctions() throws IOException {
		LOG.info("Begin test: thatRedisBackedFilterFunctions");
		NotLeakedAssertion redisBacked = new NotLeakedAssertion
				.Builder().withFalsePositiveProbability(0.001)
				.withIgnoreCase(false)
				.withPasswordDataFile("src/test/resources/testpasswords.dat")
				.withRedis("redis", 6379, "testFilter")
				.build();
		PolicyAssertion.Result result = redisBacked.verify("password");
		Assert.assertFalse(
				"Failure - redis backed word list should contain 'password'",
				result.isSuccess());
		Assert.assertEquals("Failure - result should be LEAKED_PASSWORD", 
				NotLeakedAssertion.LEAKED_PASSWORD,
				result);
		
		NotLeakedAssertion redisBacked2 = new NotLeakedAssertion
				.Builder().withFalsePositiveProbability(0.001)
				.withIgnoreCase(false)
				.withPasswordDataFile("src/test/resources/testpasswords.dat")
				.withRedis("redis", 6379, "testFilter")
				.build();
		PolicyAssertion.Result result2 = redisBacked.verify("password");
		Assert.assertFalse(
				"Failure - redis backed word list should contain 'password'",
				result2.isSuccess());
		Assert.assertEquals("Failure - result should be LEAKED_PASSWORD", 
				NotLeakedAssertion.LEAKED_PASSWORD,
				result2);
	}
	
	@Test
	public void thatCustomPasswordDataFileFunctions() throws IOException {
		NotLeakedAssertion customDataAssertion = new NotLeakedAssertion
				.Builder().withFalsePositiveProbability(0.001)
				.withIgnoreCase(false)
				.withPasswordDataFile("src/test/resources/testpasswords.dat")
				.build();
		Assert.assertEquals(
				"Failure - false positive probability should be 0.001",
				0.001,
				customDataAssertion.getFalsePositiveProbability(),
				0.0);
		Assert.assertNotNull(
				"Failure - password data file should not be null",
				customDataAssertion.getPasswordDataFile());
		Assert.assertFalse(
				"Failure - case should not be ignored",
				customDataAssertion.getIgnoreCase());
		Assert.assertTrue(
				"Failure - should have 3 passwords loaded into the filter",
				(customDataAssertion.getNumPasswords() == 3));
		Assert.assertFalse(
				"Failure - filter should contain 'password'",
				customDataAssertion.verify("password").isSuccess());
		Assert.assertTrue(
				"Failure - filter should not contain 'pASSword'",
				customDataAssertion.verify("pASSword").isSuccess());
		Assert.assertFalse(
				"Failure - filter should contain 'dog'",
				customDataAssertion.verify("dog").isSuccess());
		Assert.assertFalse(
				"Failure - filter should contain 'DOG'",
				customDataAssertion.verify("DOG").isSuccess());
		Assert.assertTrue(
				"Failure - filter should not contain 'cat'",
				customDataAssertion.verify("cat").isSuccess());
	}
}
