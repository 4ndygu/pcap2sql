package pcap2sql.orm;

import java.io.IOException;
import java.io.Serializable;
import java.sql.Timestamp;
import javax.persistence.*;

/**
 * Entity class for mapping to the table Udp4Stream
 *
 * @author Gyoergy Kohut <gyoergy.kohut@cs.uni-dortmund.de>
 */
@Entity
@SequenceGenerator(
		name="Udp4StreamSequenceGenerator",
		sequenceName="Udp4StreamSequence",
		initialValue=1,
		allocationSize=1
		)
@NamedQuery(
		name="tuple4find_Udp4Stream",
		query="SELECT c " +
				"FROM Udp4Stream c " +
				"WHERE c.stream.destIp = ?1 AND c.stream.sourceIp = ?2 AND c.destPort = ?3 AND c.sourcePort = ?4"
		)
public class Udp4Stream implements Serializable {
	public static final int PROTO = 17;
	
	@Id
	@GeneratedValue(
			strategy=GenerationType.SEQUENCE,
			generator="Udp4StreamSequenceGenerator"
			)
	private int id;
	private int destPort;
	private int sourcePort;
	@OneToOne(cascade=CascadeType.ALL)
	@JoinColumn(name="streamId")
	private Ip4Stream stream;
	
	private static final long serialVersionUID = 1L;
	
	//TODO: object fields should be initialized also when using empty constructor
	public Udp4Stream() {
//		super();
	}
	
	public Udp4Stream(String destIp, String sourceIp, int destPort, int sourcePort, Timestamp firstTime) {
		this.stream = new Ip4Stream(destIp, sourceIp, PROTO, firstTime);
		this.destPort = destPort;
		this.sourcePort = sourcePort;
	}
	
	public int getId() {
		return this.id;
	}
	
	public int getStreamId() {
		return this.stream.getId();
	}
	
	public int getDestPort() {
		return this.destPort;
	}
	
	public int getSourcePort() {
		return this.sourcePort;
	}
	
	public Ip4Stream getStream() {
		return this.stream;
	}
	
	public void addStreamSegment(int length, Timestamp time) {
		this.stream.addStreamSegment(length, time);
	}
	
	public void setLastTime(Timestamp lastTime) {
		this.stream.setLastTime(lastTime);
	}

	public void setData(String path) throws IOException {
		this.stream.setData(path);
	}
	
	public void setData(byte[] data) {
		this.stream.setData(data);
	}
}