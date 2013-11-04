package sw.malm.tomcat.security.factory;

import java.util.Properties;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.sql.DataSource;

import org.apache.tomcat.jdbc.pool.DataSourceFactory;
import org.apache.tomcat.jdbc.pool.PoolConfiguration;
import org.apache.tomcat.jdbc.pool.XADataSource;

import sw.malm.tomcat.security.util.Encryptor;

/**
 * Data source factory extended class for decrypt databases passwords.
 * 
 * @author marlonlom
 * @see http://bit.ly/1aYhhiP
 * 
 */
public class EncryptedDataSourceFactory extends DataSourceFactory {
	private static final Logger log = Logger.getLogger(EncryptedDataSourceFactory.class.getName());

	private Encryptor encryptor = null;

	public EncryptedDataSourceFactory() {
		try {
			// If you've used your own secret key, pass it in...
			encryptor = new Encryptor();
		} catch (Exception e) {
			log.severe("Error instantiating decryption class." + e.getMessage());
			throw new RuntimeException(e);
		}
	}

	@Override
	public DataSource createDataSource(Properties properties, Context context,
			boolean XA) throws Exception {
		// Here we decrypt our password.
		PoolConfiguration poolProperties = EncryptedDataSourceFactory.parsePoolProperties(properties);
		poolProperties.setPassword(encryptor.decrypt(poolProperties.getPassword()));

		// The rest of the code is copied from Tomcat's DataSourceFactory.
		if (poolProperties.getDataSourceJNDI() != null
				&& poolProperties.getDataSource() == null) {
			performJNDILookup(context, poolProperties);
		}
		org.apache.tomcat.jdbc.pool.DataSource dataSource = XA ? new XADataSource(poolProperties) : new org.apache.tomcat.jdbc.pool.DataSource(poolProperties);
		dataSource.createPool();

		return dataSource;
	}
}
