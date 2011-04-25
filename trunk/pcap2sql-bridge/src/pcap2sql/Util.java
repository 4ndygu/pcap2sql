package pcap2sql;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Properties;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.NoResultException;
import javax.persistence.Persistence;
import javax.persistence.Query;

import org.eclipse.persistence.config.PersistenceUnitProperties;
import org.eclipse.persistence.config.TargetDatabase;

import pcap2sql.orm.*;


/**
 * Helper class for pcap2sql
 * 
 * @author Gyoergy Kohut <gyoergy.kohut@cs.uni-dortmund.de>
*/
public class Util {
	private final static String DBNAME = "db";
	
	private final String jdbcUrl;
	private final String dbDirPath;
	
	private final EntityManagerFactory entityManagerFactory;
    private final EntityManager entityManager;
    
    private Iterator<Ip4Stream> allNonTcp4StreamsIterator = null;
    
    
    public Util(String workdir) {
    	jdbcUrl = "jdbc:h2:" + workdir + "/" + DBNAME;
    	dbDirPath = workdir;
    	
    	Properties properties = new Properties();
    	properties.put(PersistenceUnitProperties.JDBC_DRIVER, "org.h2.Driver");
    	properties.put(PersistenceUnitProperties.TARGET_DATABASE, TargetDatabase.Auto);
    	properties.put(PersistenceUnitProperties.JDBC_URL, jdbcUrl);
    	properties.put(PersistenceUnitProperties.JDBC_USER, "sa");
    	properties.put(PersistenceUnitProperties.JDBC_PASSWORD, "sa");
    	
    	// drop tables and create schema
    	//properties.put(PersistenceUnitProperties.DDL_GENERATION, PersistenceUnitProperties.DROP_AND_CREATE);

    	entityManagerFactory = Persistence.createEntityManagerFactory("Default", properties);
    	entityManager = entityManagerFactory.createEntityManager();
     }
    
    
    public Ip4Stream newIp4Stream(String destIp, String sourceIp, int proto, Timestamp firstTime) {
    	Ip4Stream ip4Stream = new Ip4Stream(destIp, sourceIp, proto, firstTime);

    	entityManager.getTransaction().begin();
    	entityManager.persist(ip4Stream);
    	entityManager.getTransaction().commit();
    	
    	return ip4Stream;
    }
    
    
    public Tcp4Connection newTcp4Connection(String destIp, String sourceIp, int destPort, int sourcePort, Timestamp firstTime) {
    	Tcp4Connection tcp4Connection = new Tcp4Connection(destIp, sourceIp, destPort, sourcePort, firstTime);
    	
    	entityManager.getTransaction().begin();
    	entityManager.persist(tcp4Connection);
    	entityManager.getTransaction().commit();
    	
    	return tcp4Connection;
    }
    
    
	public Udp4Stream newUdp4Stream(String destIp, String sourceIp, int destPort, int sourcePort, Timestamp firstTime) {
		Udp4Stream udp4Stream = new Udp4Stream(destIp, sourceIp, destPort, sourcePort, firstTime);
		
		entityManager.getTransaction().begin();
    	entityManager.persist(udp4Stream);
    	entityManager.getTransaction().commit();
    	
    	return udp4Stream;
	}
	
	
	public Ip4Stream findIp4Stream(String destIp, String sourceIp, int proto) {
		Query q = entityManager.createNamedQuery("tuple3find_Ip4Stream");
		q.setParameter(1, destIp);
		q.setParameter(2, sourceIp);
		q.setParameter(3, proto);
		
		Ip4Stream r = null;
		
		try {
			r = (Ip4Stream) q.getSingleResult();
		}
		catch (NoResultException e) { }
		
		return r;
	}
	
	public Tcp4Connection findTcp4Connection(int id) {
		return entityManager.find(Tcp4Connection.class, id);
	}
	
	
	public Udp4Stream findUdp4Stream(String destIp, String sourceIp, int destPort, int sourcePort) {
		Query q = entityManager.createNamedQuery("tuple4find_Udp4Stream");
		q.setParameter(1, destIp);
		q.setParameter(2, sourceIp);
		q.setParameter(3, destPort);
		q.setParameter(4, sourcePort);
		
		Udp4Stream r = null;
		
		try {
			r = (Udp4Stream) q.getSingleResult();
		}
		catch (NoResultException e) { }
		
		return r;
	}
	
	
	public List<Ip4Stream> findAllNoneTcp4Streams() {
		//TODO: create named query?
		Query q = entityManager.createQuery(
				"SELECT c from Ip4Stream c " +
				"WHERE " +
					"c.proto <> :tcp "
					);
		q.setParameter("tcp", Tcp4Connection.PROTO);
		
		return q.getResultList();
	}
	
	
	public Ip4Stream iterateAllNonTcp4Streams() {
		try {
			return allNonTcp4StreamsIterator.next();
		}
		catch (NullPointerException e) {
			allNonTcp4StreamsIterator = findAllNoneTcp4Streams().iterator();
			return iterateAllNonTcp4Streams();
		}
		catch (NoSuchElementException e) {
			allNonTcp4StreamsIterator = null;
			return null;
		}
	}

	
    public void closeDb() throws SQLException {
        // persist any changes
        entityManager.getTransaction().begin();
        entityManager.flush();
        entityManager.getTransaction().commit();
        
        // shut down JPA
        entityManager.close();
        entityManagerFactory.close();
        
        // SQL dump
        //org.h2.tools.Script.execute(jdbcUrl, "sa", "", dbDirPath + "/" + DBNAME + ".sql");
        
        // backup the DB to a zip file
        org.h2.tools.Backup.execute(dbDirPath + "/" + DBNAME + ".zip", dbDirPath, DBNAME, false);
    }
  
}
