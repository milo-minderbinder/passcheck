package co.insecurity.util.passcheck;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import orestes.bloomfilter.BloomFilter;
import orestes.bloomfilter.FilterBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import co.insecurity.util.passcheck.config.PassCheckConfig;

public class PassCheck {

	private static final Logger LOG = LoggerFactory.getLogger(PassCheck.class);
	
	private final PassCheckConfig config;
	private BloomFilter<String> filter;
	private int numAdded = 0;
	
	
	public PassCheck() {
		this(PassCheckConfig.getConfig());
	}
	
	public PassCheck(PassCheckConfig config) {
		this.config = PassCheckConfig.fromOther(config);
		try {
			loadPasswordData();
		} catch (IOException e) {
			LOG.error("Error while processing data file");
			LOG.debug("Exception message: {}", e);
		}
	}
	
	public boolean isCommon(String password) {
		if (config.getIgnoreCase())
			password = password.toLowerCase();
		
		if ((config.getMinLength() != PassCheckConfig.MIN_LENGTH_DISABLED) 
				&& password.length() < config.getMinLength()) {
			LOG.debug("Password did not meet minimum length requirements: {}", 
					password);
			return false;
		}
		if ((config.getMaxLength() != PassCheckConfig.MAX_LENGTH_DISABLED) 
				&& password.length() > config.getMaxLength()) {
			LOG.debug("Password did not meet maximum length requirements: {}", 
					password);
			return false;
		}
		if (filter.contains(password)) {
			LOG.debug("Found password in filter: {}", 
					password);
			return true;
		}
		else {
			LOG.debug("Did not find password in filter: {}", 
					password);
			return false;
		}
	}
	
	private boolean addItem(String item) {
		if ((config.getMinLength() != PassCheckConfig.MIN_LENGTH_DISABLED) 
				&& (config.getMinLength() > item.length()))
			return false;
		if ((config.getMaxLength() != PassCheckConfig.MAX_LENGTH_DISABLED) 
				&& (config.getMaxLength() < item.length()))
			return false;
		if ((config.getMaxItems() != PassCheckConfig.MAX_ITEMS_DISABLED) 
				&& ((numAdded) >= config.getMaxItems()))
			return false;
		if (config.getIgnoreCase())
			item = item.toLowerCase();
		if (filter.add(item)) {
			numAdded++;
			return true;
		} else {
			return false;
		}
	}
	
	private BufferedReader getDefaultPasswordDataReader() {
		LOG.debug("Reading password data from default data file.");
		return new BufferedReader(new InputStreamReader(
				PassCheck.class.getClassLoader()
				.getResourceAsStream(PassCheckConfig.DEFAULT_DATA_FILE)));
	}
	
	private BufferedReader getPasswordDataReader() {
		String dataFile = config.getPasswordDataFile();
		if (dataFile != null) {
			LOG.debug("Opening custom password data file: {}",
					dataFile);
			Path dataFilePath = Paths.get(dataFile);
			if (Files.exists(dataFilePath)) {
				try {
					return Files.newBufferedReader(dataFilePath);
				} catch (IOException e) {
					LOG.warn("IOException when opening custom data file: {}",
							dataFilePath);
					return getDefaultPasswordDataReader();
				}
			}
			LOG.warn("Password data file does not exist: {}", dataFile);
			return getDefaultPasswordDataReader();
		}
		return getDefaultPasswordDataReader();
	}
	
	private void loadPasswordData() throws IOException {
		LOG.info("Processing password data...");
		int numExpected = 0;
		try (BufferedReader reader = getPasswordDataReader()) {
			while (reader.readLine() != null)
				numExpected++;
		}
		// Create filter and add elements
		double fpProbability = config.getFalsePositiveProbability();
		LOG.info("Creating filter with {} false poositive probability "
				+ "and {} expected elements.", 
				fpProbability, numExpected);
		filter = new FilterBuilder(numExpected, fpProbability
				).buildBloomFilter();
		try (BufferedReader reader = getPasswordDataReader()) {
			String item = null;
			while ((item = reader.readLine()) != null)
				addItem(item);
		}
		// Verify that more passwords were not added than were initially 
		// found. Ideally, this method should lock the resource/file 
		// during processing, to prevent concurrent access issues.
		if (numAdded > numExpected) {
			String msg = String.format(
					"Attempted to add %d passwords but  expected %d."
					+ "Did the data file change?", 
					numAdded,
					numExpected);
			LOG.error(msg);
			throw new IOException(msg);
		}
	}
}