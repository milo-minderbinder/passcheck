package co.insecurity.util.passcheck;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
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
	private int numElements = 0;
	
	
	public PassCheck() {
		this.config = PassCheckConfig.getConfig();
		LOG.debug("Loaded password data successfully? {}", this.loadPasswordData());
	}
	
	public PassCheck(PassCheckConfig config) {
		this.config = config;
		LOG.debug("Loaded password data successfully? {}", this.loadPasswordData());
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
				&& ((numElements + 1) >= config.getMaxItems()))
			return false;
		if (config.getIgnoreCase())
			item = item.toLowerCase();
		if (filter.add(item)) {
			numElements++;
			return true;
		} else {
			return false;
		}
	}
	
	private boolean readDefaultPasswordData() throws IOException {
		LOG.info("Loading password data from default data file");
		int numExpectedElements = 0;
		InputStream resourceStream = PassCheck.class.getClassLoader()
				.getResourceAsStream(PassCheckConfig.DEFAULT_DATA_FILE);
		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(resourceStream))) {
			while (reader.readLine() != null) {
				numExpectedElements++;
			}
		} catch (IOException e) {
			LOG.error("Error while processing default data file");
			LOG.debug("Stack trace: {}", e);
			return false;
		}
		
		// Create filter and add elements
		filter = new FilterBuilder().expectedElements(numExpectedElements)
				.falsePositiveProbability(config.getFalsePositiveProbability())
				.buildBloomFilter();
		LOG.debug("fb: {}", filter.getFalsePositiveProbability());
		resourceStream = PassCheck.class.getClassLoader()
				.getResourceAsStream(PassCheckConfig.DEFAULT_DATA_FILE);
		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(resourceStream))) {
			String item = null;
			while ((item = reader.readLine()) != null) {
				addItem(item);
			}
		} catch (IOException e) {
			LOG.error("Error while processing default data file");
			LOG.debug("Stack trace: {}", e);
			return false;
		}
		
		if (numElements > numExpectedElements) {
			LOG.error("More elements added then expected. Added {}, but expected {}",
					numElements, numExpectedElements);
			return false;
		}
		return true;
	}
	
	private boolean readCustomPasswordData(Path dataFile, Charset charset) {
		LOG.info("Loading password data from {} with charset: {}", 
				dataFile.toAbsolutePath(), charset.name());
		try (BufferedReader reader = 
				Files.newBufferedReader(dataFile, charset)) {
			return true; //processPasswordData(reader);
		} catch (IOException e) {
			LOG.error("Error while processing data file");
			return false;
		}
	}
	
	private boolean loadPasswordData() {
		if (config.getPasswordDataFile() != null) {
			Path dataFile = Paths.get(config.getPasswordDataFile());
			if (Files.exists(dataFile))
				return readCustomPasswordData(dataFile, Charset.defaultCharset());
			else 
				LOG.error("Custom password data file does not exist: {}", 
						dataFile);
		}
		return readDefaultPasswordData();
	}
	
	public static void main(String[] args) {
		PassCheck pc = new PassCheck(PassCheckConfig.getConfig()
				.withFalsePositiveProbability(0.001)
				.withMinLength(8));
		LOG.info("{}", pc.config.getMinLength());
		LOG.info("{}", pc.config.getFalsePositiveProbability());
		pc.isCommon("dog");
		pc.isCommon("password");
		pc.isCommon("asdfaetic99c 0v97834f akjsdhfh3f3g");
	}
}