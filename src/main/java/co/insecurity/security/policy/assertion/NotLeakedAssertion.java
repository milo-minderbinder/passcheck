package co.insecurity.security.policy.assertion;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ConcurrentModificationException;

import orestes.bloomfilter.BloomFilter;
import orestes.bloomfilter.FilterBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@code PolicyAssertion} that fails if a given password is found in the 
 * configured word list of leaked and/or common passwords. This implementation 
 * offers excellent space efficiency and very fast lookup times, but has chance 
 * of reporting false positives.
 * <p>
 * During instantiation, the class creates a bloom filter and populates the 
 * filter with the words found in the password data file, and uses this filter 
 * at runtime to check for leaked/common passwords passed through the 
 * {@code verify()} method. Bloom filters are very space efficient and provide 
 * fast lookup times, and this implementation can easily support a word list 
 * with tens of millions of passwords.
 * <p>
 * The tradeoff, however, is that bloom filters have a predefined probability 
 * of reporting false positives when testing set membership. Therefore, this 
 * implementation can only confirm that a password is <i>definitely not</i> in 
 * the word list, or that it <i>probably is</i> in the word list (to some 
 * probability set at instantiation).
 * 
 * @author Milo Minderbinder
 *
 */
public class NotLeakedAssertion implements PolicyAssertion {

	private static final Logger LOG = LoggerFactory.getLogger(NotLeakedAssertion.class);
	
	/**
	 * A {@code PolicyAssertion.Result} indicating the password was found in 
	 * the word list
	 */
	public static final Result LEAKED_PASSWORD =
			new Result(false, "Password is too common, or has been leaked.");
	/**
	 * Flag to disable the limit on the number of passwords in the filter
	 */
	public static final int MAX_NUM_PASSWORDS_DISABLED = -1;

	/**
	 * Builder class for {@code NotLeakedAssertion} instantiation, which 
	 * enables clients to configure and build a {@code NotLeakedAssertion} 
	 * instance that provides reasonable defaults for unspecified configuration 
	 * parameters.
	 * 
	 * @author Milo Minderbinder
	 *
	 */
	public static class Builder {
		
		private static final String DEFAULT_DATA_FILE = "passwords.dat";
		
		private int numPasswords = 0;
		private double fpProbability;
		private int maxNumPasswords;
		private boolean ignoreCase;
		private String passwordDataFile;
		
		/**
		 * Instantiates a new {@code NotLeakedAssertion.Builder} with 
		 * reasonable default settings.
		 * <p>
		 * A call to {@code build()} on a default {@code Builder} instance 
		 * will provide a {@code NotLeakedAssertion} instance with a false 
		 * positive probability of 0.001 (1%), no limit on the number of 
		 * passwords contained in the filter, case sensitive checks against the 
		 * filter, and the default password word list included in the 
		 * distributed jar.
		 */
		public Builder() {
			this.fpProbability = 0.001;
			this.maxNumPasswords = MAX_NUM_PASSWORDS_DISABLED;
			this.ignoreCase = false;
			this.passwordDataFile = null;
		}
		
		/**
		 * Returns an updated builder that will create a 
		 * {@code NotLeakedAssertion} with the provided false positive 
		 * probability.
		 * 
		 * @param probability the false positive probability
		 * @return this {@code Builder}, updated with the specified false 
		 * positive probability
		 */
		public Builder withFalsePositiveProbability(double probability) {
			this.fpProbability = probability;
			return this;
		}
		
		/**
		 * Returns an updated builder that will create a 
		 * {@code NotLeakedAssertion} with the provided limit on the maximum 
		 * number of passwords contained in the filter.
		 * 
		 * @param numPasswords the maximum number of passwords
		 * @return this {@code Builder}, updated with the specified maximum 
		 * number of passwords permitted in the filter
		 */
		public Builder withMaxNumPasswords(int numPasswords) {
			this.maxNumPasswords = numPasswords;
			return this;
		}
		
		/**
		 * Returns an updated builder that will create a 
		 * {@code NotLeakedAssertion} with the provided setting for handling 
		 * case sensitivity.
		 * <p>
		 * To ignore case, {@code shouldIgnoreCase} should be set to true.
		 * 
		 * @param shouldIgnoreCase whether case should be ignored 
		 * @return this {@code Builder}, updated with the specified case-
		 * sensitivity setting 
		 */
		public Builder withIgnoreCase(boolean shouldIgnoreCase) {
			this.ignoreCase = shouldIgnoreCase;
			return this;
		}
		
		/**
		 * Returns an updated builder that will create a 
		 * {@code NotLeakedAssertion} with the specified password data file as 
		 * the underlying word list.
		 * <p>
		 * The data file must be UTF-8 or US-ASCII encoded, and must contain one 
		 * password per line.
		 * 
		 * @param dataFile the path to the custom password data file
		 * @return this {@code Builder}, updated with the specified data file
		 */
		public Builder withPasswordDataFile(String dataFile) {
			this.passwordDataFile = dataFile;
			return this;
		}

		/**
		 * Checks that valid configuration parameters have been set and returns 
		 * a new {@code NotLeakedAssertion} instance with those parameters.
		 * 
		 * @return a new {@code NotLeakedAssertion} instance based on the 
		 * settings configured through this {@code NotLeakedAssertion.Builder}
		 * @throws IOException if the configured password data file cannot be 
		 * processed, or is modified during processing
		 * @throws IllegalArgumentException if invalid parameters have been set 
		 * (e.g. a false positive probability less than or equal to 0)
		 */
		public NotLeakedAssertion build() throws IOException {
			if (fpProbability <= 0)
				throw new IllegalArgumentException(
						"False positive probability must be greater than 0!");
			if (maxNumPasswords < MAX_NUM_PASSWORDS_DISABLED)
				throw new IllegalArgumentException(
						"Maximum number of passwords must be greater than 0, "
						+ "or set to MAX_NUM_PASSWORDS_DISABLED to disable "
						+ "the maximum limit.");
			return new NotLeakedAssertion(loadPasswordData(), 
					numPasswords, fpProbability, maxNumPasswords, 
					ignoreCase, passwordDataFile);
		}
		
		/**
		 * Gets a {@code BufferedReader} for the custom password data file set 
		 * via the {@code withPasswordDataFile()} method, or the default data 
		 * file if a custom data file has not been set. If a custom external 
		 * data file has been specified, it is expected to be encoded with 
		 * UTF-8 or US-ASCII.
		 * 
		 * @return a {@code BufferedReader} for the configured password data 
		 * file
		 * @throws IOException if the password data file cannot be opened
		 */
		private BufferedReader getPasswordDataReader() throws IOException {
			if (passwordDataFile != null) {
				LOG.debug("Opening custom password data file: {}",
						passwordDataFile);
				Path dataFilePath = Paths.get(passwordDataFile);
				if (Files.exists(dataFilePath)) {
					try {
						return Files.newBufferedReader(dataFilePath, Charset.forName("UTF-8"));
					} catch (IOException e) {
						LOG.warn("IOException when opening custom data file: {}",
								dataFilePath);
						throw e;
					}
				} else {
					String msg = String.format("Password data file does not exist: %s", 
							passwordDataFile);
					throw new IOException(msg);
				}
			} else {
				LOG.debug("Reading password data from default data file.");
				return new BufferedReader(new InputStreamReader(
						NotLeakedAssertion.class.getClassLoader()
						.getResourceAsStream(DEFAULT_DATA_FILE)));
			}
		}
		
		/**
		 * Builds and returns a new {@code BloomFilter} containing the 
		 * passwords enumerated in the configured password data file.
		 * 
		 * @return a {@code BloomFilter} containing the password word list
		 * @throws IOException if the configured password data file cannot 
		 * be processed, or if it is modified during processing
		 */
		private BloomFilter<String> loadPasswordData() throws IOException {
			LOG.info("Processing password data...");
			BloomFilter<String> filter;
			int numExpected = 0;
			try (BufferedReader reader = getPasswordDataReader()) {
				while (reader.readLine() != null)
					numExpected++;
			}
			// Create filter and add elements
			LOG.info("Creating filter with {} false positive probability "
					+ "and {} expected elements.", 
					fpProbability, numExpected);
			filter = new FilterBuilder(numExpected, fpProbability
					).buildBloomFilter();
			try (BufferedReader reader = getPasswordDataReader()) {
				String password = null;
				while ((password = reader.readLine()) != null) {
					if ((maxNumPasswords != MAX_NUM_PASSWORDS_DISABLED) && 
							(numPasswords >= maxNumPasswords))
						return filter;
					if (ignoreCase)
						password = password.toLowerCase();
					if (filter.add(password))
						numPasswords++;
					if (numPasswords > numExpected) {
						String msg = String.format(
								"Added %d passwords but expected %d."
								+ "Did the data file change?", 
								numPasswords,
								numExpected);
						LOG.error(msg);
						throw new ConcurrentModificationException(msg);
					}
				}
			}
			return filter;
		}
	}
	
	private final BloomFilter<String> passwordFilter;
	private final int numPasswords;
	private final double fpProbability;
	private final int maxNumPasswords;
	private final boolean ignoreCase;
	private final String passwordDataFile;
	
	private NotLeakedAssertion(final BloomFilter<String> passwordFilter, 
			int numPasswords, double fpProbability, 
			int maxItems, boolean ignoreCase, String passwordDataFile) {
		this.passwordFilter = passwordFilter;
		this.numPasswords = numPasswords;
		this.fpProbability = fpProbability;
		this.maxNumPasswords = maxItems;
		this.ignoreCase = ignoreCase;
		this.passwordDataFile = passwordDataFile;
	}
	
	/**
	 * Gets the actual number of passwords stored in the filter, which will be 
	 * checked against by calls to {@code verify()}.
	 * 
	 * @return the actual number of passwords in filter
	 */
	public int getNumPasswords() {
		return numPasswords;
	}
	
	/**
	 * Gets the probability that the {@code verify()} method will incorrectly 
	 * return a failing {@code NotLeakedAssertion.LEAKED_PASSWORD} 
	 * {@code PolicyAssertion.Result} for a password that is not actually in 
	 * the word list.
	 * 
	 * @return the false positive probability
	 */
	public double getFalsePositiveProbability() {
		return fpProbability;
	}
	
	/**
	 * Gets the maximum number of passwords permitted when the filter was built 
	 * from the password data file.
	 * 
	 * @return the maximum number of passwords allowed in the filter
	 */
	public int getMaxNumPasswords() {
		return maxNumPasswords;
	}
	
	/**
	 * Gets the configured setting for case-sensitivity.
	 * 
	 * @return true if case is ignored, otherwise returns false
	 */
	public boolean getIgnoreCase() {
		return ignoreCase;
	}
	
	/**
	 * Gets the path to the custom password data file used to build the word 
	 * list and filter, if there was a custom file specified.
	 * 
	 * @return the path to the custom data file if one was used, otherwise 
	 * returns {@code null}
	 */
	public String getPasswordDataFile() {
		return passwordDataFile;
	}
	
	/**
	 * Indicates whether the given password is not contained in the configured 
	 * list of leaked and/or common passwords as required by this 
	 * {@code NotLeakedAssertion}.
	 * <p>
	 * A password will return a failing {@code Result.NULL_VALUE} if the 
	 * password is null, a failing 
	 * {@code NotLeakedAssertion.LEAKED_PASSWORD Result} if the password was 
	 * found in the filter, or {@code Result.SUCCESS} if the password passes 
	 * this assertion.
	 * 
	 * @return a failing {@code PolicyAssertion.Result} if the password is 
	 * null or if the password is found in the list of leaked/common passwords, 
	 * otherwise returns {@code Result.SUCCESS}
	 */
	@Override
	public Result verify(String password) {
		if (password == null) {
			LOG.debug("Assertion Failed - password is null");
			return Result.NULL_VALUE;
		}
		if (ignoreCase) {
			LOG.debug("Ignoring case for password: {}", password);
			password = password.toLowerCase();
		}
		if (passwordFilter.contains(password)) {
			LOG.debug("Assertion Failed - found password in filter: {}",
					password);
			return LEAKED_PASSWORD;
		}
		LOG.debug("Assertion Passed - did not find password in filter: {}", 
				password);
		return Result.SUCCESS;
	}
}