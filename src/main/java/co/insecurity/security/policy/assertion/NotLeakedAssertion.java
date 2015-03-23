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

public class NotLeakedAssertion implements PolicyAssertion {

	private static final Logger LOG = LoggerFactory.getLogger(NotLeakedAssertion.class);
	
	public static final Result LEAKED_PASSWORD =
			new Result(false, "Password is too common, or has been leaked.");
	public static final int MAX_NUM_PASSWORDS_DISABLED = -1;

	public static class Builder {
		
		private static final String DEFAULT_DATA_FILE = "passwords.dat";
		
		private int numPasswords = 0;
		private double fpProbability;
		private int maxNumPasswords;
		private boolean ignoreCase;
		private String passwordDataFile;
		
		public Builder() {
			this.fpProbability = 0.001;
			this.maxNumPasswords = MAX_NUM_PASSWORDS_DISABLED;
			this.ignoreCase = false;
			this.passwordDataFile = null;
		}
		
		public Builder withFalsePositiveProbability(double probability) {
			this.fpProbability = probability;
			return this;
		}
		
		public Builder withMaxNumPasswords(int numPasswords) {
			this.maxNumPasswords = numPasswords;
			return this;
		}
		
		public Builder withIgnoreCase(boolean shouldIgnoreCase) {
			this.ignoreCase = shouldIgnoreCase;
			return this;
		}
		
		public Builder withPasswordDataFile(String dataFile) {
			this.passwordDataFile = dataFile;
			return this;
		}

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
	
	public int getNumPasswords() {
		return numPasswords;
	}
	
	public double getFalsePositiveProbability() {
		return fpProbability;
	}
	
	public int getMaxNumPasswords() {
		return maxNumPasswords;
	}
	
	public boolean getIgnoreCase() {
		return ignoreCase;
	}
	
	public String getPasswordDataFile() {
		return passwordDataFile;
	}
	
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