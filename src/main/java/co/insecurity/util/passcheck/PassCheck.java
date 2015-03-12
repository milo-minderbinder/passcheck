package co.insecurity.util.passcheck;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import co.insecurity.util.BloomFilter;
import co.insecurity.util.passcheck.config.PassCheckConfig;

public class PassCheck {

	private static final Logger LOG = LoggerFactory.getLogger(PassCheck.class);
	
	private final PassCheckConfig config;
	private BloomFilter<String> filter;
	
	
	public PassCheck() {
		this.config = PassCheckConfig.getConfig();
		this.filter = createFilter();
	}
	
	public PassCheck(PassCheckConfig config) {
		this.config = config;
		this.filter = createFilter();
	}
	
	public boolean isCommon(String password) {
		if (config.getIgnoreCase())
			password = password.toLowerCase();
		
		if ((config.getMinLength() != -1) && password.length() < config.getMinLength()) {
			LOG.debug("Password did not meet minimum length requirements: {}", password);
			return false;
		}
		if ((config.getMaxLength() != -1) && password.length() > config.getMaxLength()) {
			LOG.debug("Password did not meet maximum length requirements: {}", password);
			return false;
		}
		if (filter.contains(password)) {
			LOG.debug("Found password in filter: {}", password);
			return true;
		}
		else {
			LOG.debug("Did not find password in filter: {}", password);
			return false;
		}
	}
	
	private TreeSet<String> processPasswordData(BufferedReader reader) 
			throws IOException {
		TreeSet<String> passwords = new TreeSet<String>();
		String line = null;
		while ((line = reader.readLine()) != null) {
			if ((config.getMinLength() != -1) && (
					config.getMinLength() > line.length()))
				continue;
			if ((config.getMaxLength() != -1) && 
					(config.getMaxLength() < line.length()))
				continue;
			if ((config.getMaxItems() != -1) && 
					((passwords.size() + 1) >= config.getMaxItems()))
				return passwords;
			if (config.getIgnoreCase())
				passwords.add(line.toLowerCase());
			else
				passwords.add(line);
		}
		return passwords;
	}
	
	private TreeSet<String> readDefaultPasswordData() {
		LOG.info("Loading password data from default data file");
		InputStream resourceStream = PassCheck.class.getClassLoader()
				.getResourceAsStream(PassCheckConfig.DEFAULT_DATA_FILE);
		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(resourceStream))) {
			return processPasswordData(reader);
		} catch (IOException e) {
			LOG.error("Error while processing default data file");
			LOG.debug("Stack trace: {}", e);
			return null;
		}
	}
	
	private TreeSet<String> readCustomPasswordData(Path dataFile, Charset charset) {
		LOG.info("Loading password data from {} with charset: {}", 
				dataFile.toAbsolutePath(), charset.name());
		try (BufferedReader reader = 
				Files.newBufferedReader(dataFile, charset)) {
			return processPasswordData(reader);
		} catch (IOException e) {
			LOG.error("Error while processing data file");
			return null;
		}
	}
	
	private TreeSet<String> loadPasswordData() {
		TreeSet<String> passwords = null;
		if (config.getPasswordDataFile() != null) {
			Path dataFile = Paths.get(config.getPasswordDataFile());
			if (!Files.exists(dataFile)) {
				LOG.error("Custom password data file does not exist: {}",
						dataFile);
				return readDefaultPasswordData();
			}
			for (Charset charset : Charset.availableCharsets().values()) {
				passwords = readCustomPasswordData(dataFile, charset);
				if (passwords != null) {
					LOG.debug("Loaded password file with charset: {}", 
							charset.name());
					return passwords;
				}
			}
			LOG.error("Unable to read custom password data file with any charset: {}", 
					dataFile);
		}
		return readDefaultPasswordData();
	}
	
	private BloomFilter<String> createFilter() {
		TreeSet<String> passwordSet = loadPasswordData();
		LOG.info("Creating BloomFilter with falsePositiveProbability={} "
				+ "and expectedNumberOfElements={}", 
				config.getFalsePositiveProbability(), passwordSet.size());
		filter = new BloomFilter<String>(
				config.getFalsePositiveProbability(), 
				passwordSet.size());
		
		LOG.debug("Adding {} passwords to filter...", passwordSet.size());
		filter.addAll(passwordSet);

		return filter;
	}
	
	public static void main(String[] args) {
		PassCheck pc = new PassCheck();
		pc.isCommon("password");
		pc.isCommon("dog");
		pc.isCommon("oibeinvniciapifgpiupioufvjkpausepioupiofv8994t8hbv");
	}
}