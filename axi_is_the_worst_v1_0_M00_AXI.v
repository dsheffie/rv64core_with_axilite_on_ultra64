
`timescale 1 ns / 1 ps

module axi_is_the_worst_v1_0_M00_AXI #
  (
   // Users to add parameters here
   
   // User parameters ends
   // Do not modify the parameters beyond this line

   // Base address of targeted slave
   parameter  C_M_TARGET_SLAVE_BASE_ADDR	= 32'h40000000,
   // Burst Length. Supports 1, 2, 4, 8, 16, 32, 64, 128, 256 burst lengths
   parameter integer C_M_AXI_BURST_LEN	= 16,
   // Thread ID Width
   parameter integer C_M_AXI_ID_WIDTH	= 1,
   // Width of Address Bus
   parameter integer C_M_AXI_ADDR_WIDTH	= 32,
   // Width of Data Bus
   parameter integer C_M_AXI_DATA_WIDTH	= 32,
   // Width of User Write Address Bus
   parameter integer C_M_AXI_AWUSER_WIDTH	= 0,
   // Width of User Read Address Bus
   parameter integer C_M_AXI_ARUSER_WIDTH	= 0,
   // Width of User Write Data Bus
   parameter integer C_M_AXI_WUSER_WIDTH	= 0,
   // Width of User Read Data Bus
   parameter integer C_M_AXI_RUSER_WIDTH	= 0,
   // Width of User Response Bus
   parameter integer C_M_AXI_BUSER_WIDTH	= 0
   )
   (
    // Users to add ports here
    input wire				     rv_reset,
    input wire				     step_txn,
    input wire				     ack_txn,
    input wire [31:0]			     baseaddr,
    output wire [63:0]			     txn_cnt,
    output wire [63:0]			     txn_lat,
    
    output wire [127:0]			     load_data,
    output wire [3:0]			     state,
    output wire [31:0]			     last_addr,
    output wire [31:0]			     last_data,

    input wire [127:0]			     mem_req_store_data,
    
    input wire				     mem_req_valid,
    input wire [3:0]			     mem_opcode,
    output wire				     mem_rsp_valid,
    output wire				     mem_req_gnt,

    input wire [1:0]			     mem_req_tag,
    output wire [1:0]			     mem_rsp_tag,
    // User ports ends
    // Do not modify the ports beyond this line

    // Initiate AXI transactions
    input wire				     INIT_AXI_TXN,
    // Asserts when transaction is complete
    output wire				     TXN_DONE,
    // Asserts when ERROR is detected
    output reg				     ERROR,
    // Global Clock Signal.
    input wire				     M_AXI_ACLK,
    // Global Reset Singal. This Signal is Active Low
    input wire				     M_AXI_ARESETN,
    // Master Interface Write Address ID
    output wire [C_M_AXI_ID_WIDTH-1 : 0]     M_AXI_AWID,
    // Master Interface Write Address
    output wire [C_M_AXI_ADDR_WIDTH-1 : 0]   M_AXI_AWADDR,
    // Burst length. The burst length gives the exact number of transfers in a burst
    output wire [7 : 0]			     M_AXI_AWLEN,
    // Burst size. This signal indicates the size of each transfer in the burst
    output wire [2 : 0]			     M_AXI_AWSIZE,
    // Burst type. The burst type and the size information, 
    // determine how the address for each transfer within the burst is calculated.
    output wire [1 : 0]			     M_AXI_AWBURST,
    // Lock type. Provides additional information about the
    // atomic characteristics of the transfer.
    output wire				     M_AXI_AWLOCK,
    // Memory type. This signal indicates how transactions
    // are required to progress through a system.
    output wire [3 : 0]			     M_AXI_AWCACHE,
    // Protection type. This signal indicates the privilege
    // and security level of the transaction, and whether
    // the transaction is a data access or an instruction access.
    output wire [2 : 0]			     M_AXI_AWPROT,
    // Quality of Service, QoS identifier sent for each write transaction.
    output wire [3 : 0]			     M_AXI_AWQOS,
    // Optional User-defined signal in the write address channel.
    output wire [C_M_AXI_AWUSER_WIDTH-1 : 0] M_AXI_AWUSER,
    // Write address valid. This signal indicates that
    // the channel is signaling valid write address and control information.
    output wire				     M_AXI_AWVALID,
    // Write address ready. This signal indicates that
    // the slave is ready to accept an address and associated control signals
    input wire				     M_AXI_AWREADY,
    // Master Interface Write Data.
    output wire [C_M_AXI_DATA_WIDTH-1 : 0]   M_AXI_WDATA,
    // Write strobes. This signal indicates which byte
    // lanes hold valid data. There is one write strobe
    // bit for each eight bits of the write data bus.
    output wire [C_M_AXI_DATA_WIDTH/8-1 : 0] M_AXI_WSTRB,
    // Write last. This signal indicates the last transfer in a write burst.
    output wire				     M_AXI_WLAST,
    // Optional User-defined signal in the write data channel.
    output wire [C_M_AXI_WUSER_WIDTH-1 : 0]  M_AXI_WUSER,
    // Write valid. This signal indicates that valid write
    // data and strobes are available
    output wire				     M_AXI_WVALID,
    // Write ready. This signal indicates that the slave
    // can accept the write data.
    input wire				     M_AXI_WREADY,
    // Master Interface Write Response.
    input wire [C_M_AXI_ID_WIDTH-1 : 0]	     M_AXI_BID,
    // Write response. This signal indicates the status of the write transaction.
    input wire [1 : 0]			     M_AXI_BRESP,
    // Optional User-defined signal in the write response channel
    input wire [C_M_AXI_BUSER_WIDTH-1 : 0]   M_AXI_BUSER,
    // Write response valid. This signal indicates that the
    // channel is signaling a valid write response.
    input wire				     M_AXI_BVALID,
    // Response ready. This signal indicates that the master
    // can accept a write response.
    output wire				     M_AXI_BREADY,
    // Master Interface Read Address.
    output wire [C_M_AXI_ID_WIDTH-1 : 0]     M_AXI_ARID,
    // Read address. This signal indicates the initial
    // address of a read burst transaction.
    output wire [C_M_AXI_ADDR_WIDTH-1 : 0]   M_AXI_ARADDR,
    // Burst length. The burst length gives the exact number of transfers in a burst
    output wire [7 : 0]			     M_AXI_ARLEN,
    // Burst size. This signal indicates the size of each transfer in the burst
    output wire [2 : 0]			     M_AXI_ARSIZE,
    // Burst type. The burst type and the size information, 
    // determine how the address for each transfer within the burst is calculated.
    output wire [1 : 0]			     M_AXI_ARBURST,
    // Lock type. Provides additional information about the
    // atomic characteristics of the transfer.
    output wire				     M_AXI_ARLOCK,
    // Memory type. This signal indicates how transactions
    // are required to progress through a system.
    output wire [3 : 0]			     M_AXI_ARCACHE,
    // Protection type. This signal indicates the privilege
    // and security level of the transaction, and whether
    // the transaction is a data access or an instruction access.
    output wire [2 : 0]			     M_AXI_ARPROT,
    // Quality of Service, QoS identifier sent for each read transaction
    output wire [3 : 0]			     M_AXI_ARQOS,
    // Optional User-defined signal in the read address channel.
    output wire [C_M_AXI_ARUSER_WIDTH-1 : 0] M_AXI_ARUSER,
    // Write address valid. This signal indicates that
    // the channel is signaling valid read address and control information
    output wire				     M_AXI_ARVALID,
    // Read address ready. This signal indicates that
    // the slave is ready to accept an address and associated control signals
    input wire				     M_AXI_ARREADY,
    // Read ID tag. This signal is the identification tag
    // for the read data group of signals generated by the slave.
    input wire [C_M_AXI_ID_WIDTH-1 : 0]	     M_AXI_RID,
    // Master Read Data
    input wire [C_M_AXI_DATA_WIDTH-1 : 0]    M_AXI_RDATA,
    // Read response. This signal indicates the status of the read transfer
    input wire [1 : 0]			     M_AXI_RRESP,
    // Read last. This signal indicates the last transfer in a read burst
    input wire				     M_AXI_RLAST,
    // Optional User-defined signal in the read address channel.
    input wire [C_M_AXI_RUSER_WIDTH-1 : 0]   M_AXI_RUSER,
    // Read valid. This signal indicates that the channel
    // is signaling the required read data.
    input wire				     M_AXI_RVALID,
    // Read ready. This signal indicates that the master can
    // accept the read data and response information.
    output wire				     M_AXI_RREADY
    );

   reg [127:0]				     r_load_data;
   reg [127:0]				     n_store_data, r_store_data;   
   reg					     r_mem_rsp_valid, n_mem_rsp_valid;
   reg [1:0]				     r_tag,n_tag;
   
   assign mem_rsp_valid = r_mem_rsp_valid;
   assign mem_rsp_tag = r_tag;
   
   reg [3:0]	      r_state, n_state;
   assign state = r_state;
   
   reg [63:0]	      r_cnt, n_cnt, r_lat, n_lat;
   assign txn_cnt = r_cnt;
   assign txn_lat = r_lat;
   

   //I/O Connections. Write Address (AW)
   assign M_AXI_AWID	= 'b0;
   assign M_AXI_ARID	= 'b0;

   
   //The AXI address is a concatenation of the target base address + active offset range
   //Burst LENgth is number of transaction beats, minus 1
   
   assign M_AXI_AWLEN	= 8'd0;
   assign M_AXI_ARLEN	= 8'd0;
   //Size should be C_M_AXI_DATA_WIDTH, in 2^SIZE bytes, otherwise narrow bursts are used
   assign M_AXI_AWSIZE	= 3'd4; /* 16 bytes */
   assign M_AXI_ARSIZE	= 3'd4;
   
   //INCR burst type is usually used, except for keyhole bursts
   assign M_AXI_AWBURST	= 2'b00;
   assign M_AXI_AWLOCK	= 1'b0;
   //Update value to 4'b0011 if coherent accesses to be used via the Zynq ACP port. 
   assign M_AXI_AWCACHE	= 4'b0010;
   assign M_AXI_AWPROT	= 3'h0;
   assign M_AXI_AWQOS	= 4'h0;
   assign M_AXI_AWUSER	= 'b1;

   //Write Data(W)

   assign M_AXI_WUSER	= 'b0;

   //Read Address (AR)


   //INCR burst type is usually used, except for keyhole bursts
   assign M_AXI_ARBURST	= 2'b00;
   assign M_AXI_ARLOCK	= 1'b0;
   
   //Update value to 4'b0011 if coherent accesses to be used via the Zynq ACP port.  
   assign M_AXI_ARCACHE	= 4'b0010;
   assign M_AXI_ARPROT	= 3'h0;
   assign M_AXI_ARQOS	= 4'h0;
   assign M_AXI_ARUSER	= 'b1;
   
   //Example design I/O
   assign TXN_DONE	= 1'b1;


   reg [31:0]	      r_addr, n_addr;
   reg [31:0]	      r_last_addr, n_last_addr;   
   reg		      r_awvalid, n_awvalid;
   reg		      r_arvalid, n_arvalid;
   reg		      t_mem_req_gnt;
   reg		      r_wvalid, n_wvalid;
   reg		      r_bready, n_bready;
   reg		      n_rready, r_rready;
   reg		      r_ack_wr_early , n_ack_wr_early;
   
   localparam	      IDLE = 4'd0;
   localparam	      WR_CH = 4'd1;
   localparam	      WR_RSP = 4'd2;
   localparam	      RD_CH = 4'd3;
   localparam	      RD_RSP = 4'd4;
   localparam	      RD_DEAD = 4'd5;
   localparam	      WR_DEAD = 4'd6;
   localparam	      WAIT_ACK = 4'd7;
   localparam	      WAIT_REQ = 4'd8;
   
   wire				   w_reset = (M_AXI_ARESETN == 1'b0) | rv_reset;
   always@(posedge M_AXI_ACLK)
     begin
	r_state <= w_reset ? IDLE : n_state;
	r_rready <= w_reset ? 1'b0 : n_rready;
	r_awvalid <= w_reset ? 1'b0 : n_awvalid;
	r_arvalid <= w_reset ? 1'b0 : n_arvalid;
	r_wvalid <= w_reset ? 1'b0 : n_wvalid;
	r_bready <= w_reset ? 1'b0 : n_bready;
	r_mem_rsp_valid <= w_reset ? 1'b0 : n_mem_rsp_valid;
	r_addr <= w_reset ? 32'hdeadbee0 : n_addr;
	r_tag <= w_reset ? 'd0 : n_tag;
	r_last_addr <= w_reset ? 32'hcafebeb0 : n_last_addr;
	r_ack_wr_early <= w_reset ? 1'b0 : n_ack_wr_early;
     end

   assign M_AXI_ARADDR	= r_addr;
   assign M_AXI_ARVALID = r_arvalid;

   assign M_AXI_RREADY	= r_rready;
   
   assign M_AXI_AWVALID	= r_awvalid;
   assign M_AXI_AWADDR	= r_addr;
   
   assign M_AXI_WVALID	= r_awvalid;
   
   assign M_AXI_WDATA	= r_store_data;
   assign M_AXI_WSTRB	= 16'hffff;

   assign M_AXI_WLAST	= r_awvalid;   
   assign M_AXI_BREADY	= (r_state == WR_CH) | (r_state == WR_RSP);
   
   assign mem_req_gnt = t_mem_req_gnt;
   
   wire w_wr_req = mem_req_valid & (mem_opcode == 4'd7);
   wire	w_rd_req = mem_req_valid & (mem_opcode == 4'd4);

   
   always@(posedge M_AXI_ACLK)
     begin
        r_cnt <= w_reset ? 'd0 : n_cnt;
	r_lat <= w_reset ? 'd0 : n_lat;
     end // always@ (posedge M_AXI_ACLK)
   
   always@(*)
     begin
	n_cnt = r_cnt;
	n_lat = r_lat;
	if(t_mem_req_gnt)
	  begin
	     n_cnt = r_cnt + 'd1;
	  end
	if(r_state != IDLE)
	  begin
	     n_lat = r_lat + 'd1;
	  end
     end // always@ (*)

   
   always@(*)
     begin
	n_state = r_state;
	n_tag = r_tag;
	n_addr = r_addr;
	n_last_addr = r_last_addr;
	n_awvalid = r_awvalid;
	n_arvalid = r_arvalid;
	
	n_wvalid = 1'b0;
	n_rready = r_rready;
	n_bready = r_bready;
	n_mem_rsp_valid = 1'b0;
	n_store_data = r_store_data;
	n_ack_wr_early = 1'b0;
	//combinational
	t_mem_req_gnt = 1'b0;
	
	case(r_state)
	  IDLE:
	    begin
	       if(w_wr_req)
		 begin
		    n_addr = baseaddr;		    	       		    
		    n_state = WR_CH;
		    n_awvalid = 1'b1;
		    n_tag = mem_req_tag;
		    t_mem_req_gnt = 1'b1;
		    n_store_data = mem_req_store_data;	
		    n_ack_wr_early = 1'b1;
		 end
	       else if(w_rd_req)
		 begin
		    n_addr = baseaddr;		    	       		    
		    n_state = RD_CH;
		    n_arvalid = 1'b1;
		    n_rready = 1'b1;
		    n_tag = mem_req_tag;		    
		    t_mem_req_gnt = 1'b1;		    
		 end
	    end // case: IDLE
	  WR_CH:
	    begin
	       n_mem_rsp_valid = r_ack_wr_early;
	       if(M_AXI_AWVALID & M_AXI_AWREADY & M_AXI_WVALID & M_AXI_WREADY)
		 begin
		    n_last_addr = r_addr;
		    n_state = WR_RSP;
		    n_awvalid = 1'b0;
		 end
	    end
	  WR_RSP:
	    begin
	       if(M_AXI_BVALID)
		 begin
		    if(step_txn)
		      begin
			 n_state = WR_DEAD;
		      end
		    else
		      begin
			 n_state = IDLE;
		      end
		 end
	    end
	  RD_CH:
	    begin
	       if(M_AXI_ARREADY)
		 begin
		    n_last_addr = r_addr;		    
		    n_state = RD_RSP;
		    n_arvalid = 1'b0;
		 end
	    end
	  RD_RSP:
	    begin
	       if(M_AXI_RVALID)
		 begin
		    if(step_txn)
		      begin
			 n_state = RD_DEAD;
		      end
		    else
		      begin
			 n_state = IDLE;
		      end
		    n_mem_rsp_valid = 1'b1;
		    n_rready = 1'b0;		    
		 end
	    end
	  RD_DEAD:
	    begin
	       n_state = ack_txn ? WAIT_ACK : RD_DEAD;
	    end
	  WR_DEAD:
	    begin
	       n_state = ack_txn ? WAIT_ACK : WR_DEAD;
	    end
	  WAIT_ACK:
	    begin
	       n_state = ack_txn ? WAIT_ACK : IDLE;
	    end
	endcase
     end // always@ (*)



   assign load_data = r_load_data;
   
   always@(posedge M_AXI_ACLK)
     begin
	r_store_data <= n_store_data;
	if((r_state == RD_RSP) & M_AXI_RVALID)
	  begin
	     r_load_data <= M_AXI_RDATA;
	  end
     end // always @ (posedge M_AXI_ACLK)

      
   
   assign last_addr = r_addr;
   assign last_data = r_load_data[31:0];

endmodule
