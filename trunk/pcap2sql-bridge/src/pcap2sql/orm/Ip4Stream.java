package pcap2sql.orm;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

import javax.persistence.*;

/**
 * Entity class for mapping to the table Ip4Stream
 *
 * @author Gyoergy Kohut <gyoergy.kohut@cs.uni-dortmund.de>
 */
@Entity
@SequenceGenerator(
		name="Ip4StreamSequenceGenerator",
		sequenceName="Ip4StreamSequence",
		initialValue=1,
		allocationSize=1
		)
@NamedQuery(
		name="tuple3find_Ip4Stream",
		query="SELECT c " +
				"FROM Ip4Stream c " +
				"WHERE c.destIp = ?1 AND c.sourceIp = ?2 AND c.proto = ?3"
		)
public class Ip4Stream implements Serializable {
	@Id
	@GeneratedValue(
			strategy=GenerationType.SEQUENCE,
			generator="Ip4StreamSequenceGenerator"
			)
	private int id;
	@Column(length=15)
	private String destIp;
	@Column(length=15)
	private String sourceIp;
	private int proto;
	private Timestamp firstTime;
	private Timestamp lastTime;
	@Basic(fetch=FetchType.LAZY)
	@Lob
	private byte[] data;
	@ElementCollection
	@CollectionTable(
			name="StreamSegment",
			joinColumns={
					@JoinColumn(
							name="streamId",
							columnDefinition="INT" //TODO: this is a workaround as I got VARCHAR (EclipseLink problem?)
							)
					}
			)
	private List<StreamSegment> streamSegmentList = new LinkedList<StreamSegment>();
		
	private static final long serialVersionUID = 1L;
		
	public Ip4Stream() {
//		super();
	}
	
	public Ip4Stream(String destIp, String sourceIp, int proto, Timestamp firstTime) {
		super();
		this.destIp = destIp;
		this.sourceIp = sourceIp;
		this.proto = proto;
		this.firstTime = firstTime;
	}

	public int getId() {
		return this.id;
	}
	
	public String getDestIp() {
		return this.destIp;
	}
	
	public String getSourceIp() {
		return this.sourceIp;
	}
	
	public int getProto() {
		return this.proto;
	}
	
	public Timestamp getFirstTime() {
		return this.firstTime;
	}
	
	public Timestamp getLastTime() {
		return this.lastTime;
	}

	public void setLastTime(Timestamp lastTime) {
		this.lastTime = lastTime;
	}
	
	public byte[] getData() {
		return this.data;
	}

	//TODO: stream the blob
	public void setData(String path) throws IOException {
		File file = new File(path);
		FileInputStream fileInputStream = new FileInputStream(file);
		byte[] data = new byte[(int) file.length()];
		fileInputStream.read(data);
		
		this.data = data;
		
		fileInputStream.close();
	}
	
	public void setData(byte[] data) {
		this.data = data;
	}
	
	public void addStreamSegment(int length, Timestamp time) {
		long number;
		long offset;
		StreamSegment lastStreamSegment = null;
		
		try {
			lastStreamSegment = ((LinkedList<StreamSegment>) this.streamSegmentList).getLast();
			number = lastStreamSegment.getNumber() + 1;
			offset = lastStreamSegment.getOffset() + lastStreamSegment.getLength();
		}
		catch (NoSuchElementException e) { 
			number = 1;
			offset = 0;
		}
		
		this.streamSegmentList.add(new StreamSegment(number, offset, length, time));
	}
	
	public List<StreamSegment> getStreamSegmentList() {
		return this.streamSegmentList;
	}
}