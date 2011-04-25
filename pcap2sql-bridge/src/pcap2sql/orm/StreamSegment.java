package pcap2sql.orm;

import java.io.Serializable;
import java.sql.Timestamp;
import javax.persistence.*;

/**
 * Entity class for mapping to the table StreamSegment
 *
 * @author Gyoergy Kohut <gyoergy.kohut@cs.uni-dortmund.de>
 */
@Embeddable
public class StreamSegment implements Serializable {
	private long number;
	private long offset;
	private long length;
	private Timestamp time;
	
	private static final long serialVersionUID = 1L;

	public StreamSegment() {
//		super();
	}
	
	public StreamSegment(long number, long offset, long length, Timestamp time) {
		this.number = number;
		this.offset = offset;
		this.length = length;
		this.time = time;
	}
	
	public long getNumber() {
		return this.number;
	}
	
	public long getOffset() {
		return this.offset;
	}
	
	public long getLength() {
		return this.length;
	}
	
	public Timestamp getTime() {
		return this.time;
	}
}