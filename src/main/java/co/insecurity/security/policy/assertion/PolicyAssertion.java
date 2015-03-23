package co.insecurity.security.policy.assertion;

/**
 * The {@code PolicyAssertion} interface defines a single method, 
 * {@code verify}, which should take a password string and return a 
 * {@code PolicyAssertion.Result} indicating if the assertion is true for the 
 * given password and why.
 * 
 * @author Milo Minderbinder
 *
 */
public interface PolicyAssertion {

	/**
	 * A {@code PolicyAssertion.Result} encapsulates the success or failure, 
	 * and the corresponding reason, of a tested assertion against a given 
	 * password.
	 * 
	 * For convenience, {@code PolicyAssertion.Result} pre-defines several 
	 * static members which define common result types (e.g. generic success).
	 * 
	 * @author Milo Minderbinder
	 *
	 */
	public class Result {
		/**
		 * A generic success result.
		 */
		public static final Result SUCCESS = 
				new Result(true, "Password meets assertion criteria.");
		/**
		 * A generic failure result due to a null password.
		 */
		public static final Result NULL_VALUE = 
				new Result(false, "Supplied password value is null.");

		private boolean success;
		private String reason;
		
		/**
		 * Instantiates a new {@code PolicyAssertion.Result}.
		 * @param success indicates whether the {@code PolicyAssertion} is true 
		 * for a given password
		 * @param reason indicates the reason for {@code Result} value
		 */
		public Result(boolean success, String reason) {
			this.success = success;
			this.reason = reason;
		}
		
		/**
		 * Indicates if the {@code PolicyAssertion} held for a given password.
		 * 
		 * @return true if the assertion was true for the password, otherwise 
		 * returns false
		 */
		public boolean isSuccess() { return success; }
		
		/**
		 * Provides an explanation for the success or failure of the assertion 
		 * for a password.
		 * @return an explanation of the success or failure
		 */
		public String getReason() { return reason; }
	}
	
	/**
	 * Implementations should return a {@code PolicyAssertion.Result} indicating 
	 * whether the given password meets the assertion criteria and providing an 
	 * accompanying justification.
	 * 
	 * As an example, a {@code PolicyAssertion} might implement the 
	 * {@code verify} method to test the assertion that the supplied password 
	 * is at least 10 characters long and contains a digit.
	 * 
	 * @param password the password to verify against the assertion definition
	 * @return a {@code PolicyAssertion.Result} indicating whether the 
	 * assertion is met
	 */
	public Result verify(String password);
}