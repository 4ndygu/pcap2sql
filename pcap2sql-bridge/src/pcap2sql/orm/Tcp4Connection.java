package pcap2sql.orm;

import java.io.IOException;
import java.io.Serializable;
import java.sql.Timestamp;
import javax.persistence.*;

/**
 * Entity class for mapping to the table Tcp4Connection
 *
 * @author Gyoergy Kohut <gyoergy.kohut@cs.uni-dortmund.de>
 */
@Entity
@SequenceGenerator(
		name="Tcp4ConnectionSequenceGenerator",
		sequenceName="Tcp4ConnectionSequence",
		initialValue=1,
		allocationSize=1
		)
public class Tcp4Connection implements Serializable {
	public static final int PROTO = 6;
	
	@Id
	@GeneratedValue(
			strategy=GenerationType.SEQUENCE,
			generator="Tcp4ConnectionSequenceGenerator"
			)
	private int id;
	private int destPort;
	private int sourcePort;
	private Timestamp lastTime;
	private int finalStatus;
	@OneToOne(cascade=CascadeType.ALL)
	@JoinColumn(name="outStreamId")
	private Ip4Stream outStream;
	@OneToOne(cascade=CascadeType.ALL)
	@JoinColumn(name="inStreamId")
	private Ip4Stream inStream;
	private boolean incoming;

	private static final long serialVersionUID = 1L;

	public Tcp4Connection() {
//		super();
	}
	
	public Tcp4Connection(String destIp, String sourceIp, int destPort, int sourcePort, Timestamp firstTime) {
		this.outStream = new Ip4Stream(destIp, sourceIp, PROTO, firstTime);
		this.inStream = new Ip4Stream(sourceIp, destIp, PROTO, firstTime);
		this.destPort = destPort;
		this.sourcePort = sourcePort;
	}
	
	public int getId() {
		return this.id;
	}
	
	public int getOutStreamId() {
		return this.outStream.getId();
	}
	
	public int getInStreamId() {
		return this.inStream.getId();
	}
	
	public int getDestPort() {
		return this.destPort;
	}
	
	public int getSourcePort() {
		return this.sourcePort;
	}
	
	public Timestamp getLastTime() {
		return this.lastTime;
	}

	public void setLastTime(Timestamp lastTime) {
		this.lastTime = lastTime;
	}
	
	public int getFinalStatus() {
		return this.finalStatus;
	}
	
	public void setFinalStatus(int finalStatus) {
		this.finalStatus = finalStatus;
	}
	
	public boolean getIncoming() {
		return this.incoming;
	}

	public void setIncoming(boolean incoming) {
		this.incoming = incoming;
	}
	
	public Ip4Stream getOutStream() {
		return this.outStream;
	}
	
	public Ip4Stream getInStream() {
		return this.inStream;
	}

	public void setOutStreamLastTime(Timestamp lastTime) {
		this.outStream.setLastTime(lastTime);
	}
	
	public void setInStreamLastTime(Timestamp lastTime) {
		this.inStream.setLastTime(lastTime);
	}
	
	public void addOutStreamSegment(int length, Timestamp time) {
		this.outStream.addStreamSegment(length, time);
	}
	
	public void addInStreamSegment(int length, Timestamp time) {
		this.inStream.addStreamSegment(length, time);
	}
	
	public void setOutStreamData(String path) throws IOException {
		this.outStream.setData(path);
	}
	
	public void setOutStreamData(byte[] data) {
		this.outStream.setData(data);
	}
	
	public void setInStreamData(String path) throws IOException {
		this.inStream.setData(path);
	}
	
	public void setInStreamData(byte[] data) {
		this.inStream.setData(data);
	}
}