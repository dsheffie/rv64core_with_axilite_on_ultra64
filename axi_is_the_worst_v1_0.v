
`timescale 1 ns / 1 ps


module axi_is_the_worst_v1_0 #
  (
   // Users to add parameters here

   // User parameters ends
   // Do not modify the parameters beyond this line


   // Parameters of Axi Slave Bus Interface S00_AXI
   parameter integer C_S00_AXI_DATA_WIDTH = 32,
   parameter integer C_S00_AXI_ADDR_WIDTH = 8, 
		     
   // Parameters of Axi Master Bus Interface M00_AXI
   parameter C_M00_AXI_TARGET_SLAVE_BASE_ADDR = 32'h40000000,
   parameter integer C_M00_AXI_BURST_LEN = 1,
   parameter integer C_M00_AXI_ID_WIDTH = 1,
   parameter integer C_M00_AXI_ADDR_WIDTH = 32,
   parameter integer C_M00_AXI_DATA_WIDTH = 128,
   parameter integer C_M00_AXI_AWUSER_WIDTH = 0,
   parameter integer C_M00_AXI_ARUSER_WIDTH = 0,
   parameter integer C_M00_AXI_WUSER_WIDTH = 0,
   parameter integer C_M00_AXI_RUSER_WIDTH = 0,
   parameter integer C_M00_AXI_BUSER_WIDTH = 0
   )
   (
    // Users to add ports here

    // User ports ends
    // Do not modify the ports beyond this line


    // Ports of Axi Slave Bus Interface S00_AXI
    input wire 					s00_axi_aclk,
    input wire 					s00_axi_aresetn,
    input wire [C_S00_AXI_ADDR_WIDTH-1 : 0] 	s00_axi_awaddr,
    input wire [2 : 0] 				s00_axi_awprot,
    input wire 					s00_axi_awvalid,
    output wire 				s00_axi_awready,
    input wire [C_S00_AXI_DATA_WIDTH-1 : 0] 	s00_axi_wdata,
    input wire [(C_S00_AXI_DATA_WIDTH/8)-1 : 0] s00_axi_wstrb,
    input wire 					s00_axi_wvalid,
    output wire 				s00_axi_wready,
    output wire [1 : 0] 			s00_axi_bresp,
    output wire 				s00_axi_bvalid,
    input wire 					s00_axi_bready,
    input wire [C_S00_AXI_ADDR_WIDTH-1 : 0] 	s00_axi_araddr,
    input wire [2 : 0] 				s00_axi_arprot,
    input wire 					s00_axi_arvalid,
    output wire 				s00_axi_arready,
    output wire [C_S00_AXI_DATA_WIDTH-1 : 0] 	s00_axi_rdata,
    output wire [1 : 0] 			s00_axi_rresp,
    output wire 				s00_axi_rvalid,
    input wire 					s00_axi_rready,

    // Ports of Axi Master Bus Interface M00_AXI
    input wire 					m00_axi_init_axi_txn,
    output wire 				m00_axi_txn_done,
    output wire 				m00_axi_error,
    input wire 					m00_axi_aclk,
    input wire 					m00_axi_aresetn,
    output wire [C_M00_AXI_ID_WIDTH-1 : 0] 	m00_axi_awid,
    output wire [C_M00_AXI_ADDR_WIDTH-1 : 0] 	m00_axi_awaddr,
    output wire [7 : 0] 			m00_axi_awlen,
    output wire [2 : 0] 			m00_axi_awsize,
    output wire [1 : 0] 			m00_axi_awburst,
    output wire 				m00_axi_awlock,
    output wire [3 : 0] 			m00_axi_awcache,
    output wire [2 : 0] 			m00_axi_awprot,
    output wire [3 : 0] 			m00_axi_awqos,
    output wire [C_M00_AXI_AWUSER_WIDTH-1 : 0] 	m00_axi_awuser,
    output wire 				m00_axi_awvalid,
    input wire 					m00_axi_awready,
    output wire [C_M00_AXI_DATA_WIDTH-1 : 0] 	m00_axi_wdata,
    output wire [C_M00_AXI_DATA_WIDTH/8-1 : 0] 	m00_axi_wstrb,
    output wire 				m00_axi_wlast,
    output wire [C_M00_AXI_WUSER_WIDTH-1 : 0] 	m00_axi_wuser,
    output wire 				m00_axi_wvalid,
    input wire 					m00_axi_wready,
    input wire [C_M00_AXI_ID_WIDTH-1 : 0] 	m00_axi_bid,
    input wire [1 : 0] 				m00_axi_bresp,
    input wire [C_M00_AXI_BUSER_WIDTH-1 : 0] 	m00_axi_buser,
    input wire 					m00_axi_bvalid,
    output wire 				m00_axi_bready,
    output wire [C_M00_AXI_ID_WIDTH-1 : 0] 	m00_axi_arid,
    output wire [C_M00_AXI_ADDR_WIDTH-1 : 0] 	m00_axi_araddr,
    output wire [7 : 0] 			m00_axi_arlen,
    output wire [2 : 0] 			m00_axi_arsize,
    output wire [1 : 0] 			m00_axi_arburst,
    output wire 				m00_axi_arlock,
    output wire [3 : 0] 			m00_axi_arcache,
    output wire [2 : 0] 			m00_axi_arprot,
    output wire [3 : 0] 			m00_axi_arqos,
    output wire [C_M00_AXI_ARUSER_WIDTH-1 : 0] 	m00_axi_aruser,
    output wire 				m00_axi_arvalid,
    input wire 					m00_axi_arready,
    input wire [C_M00_AXI_ID_WIDTH-1 : 0] 	m00_axi_rid,
    input wire [C_M00_AXI_DATA_WIDTH-1 : 0] 	m00_axi_rdata,
    input wire [1 : 0] 				m00_axi_rresp,
    input wire 					m00_axi_rlast,
    input wire [C_M00_AXI_RUSER_WIDTH-1 : 0] 	m00_axi_ruser,
    input wire 					m00_axi_rvalid,
    output wire 				m00_axi_rready
    );
   wire [31:0] 					w_controlreg,w_baseaddr,w_status;
   wire [31:0]					w_addrmask;
   
   wire [31:0] 					w_mem_req_addr;
   wire [31:0] 					w_axi_addr = w_baseaddr+(w_mem_req_addr & w_addrmask);

   wire [127:0]					w_mem_req_store_data;
   
   
   //outputs to axi slave
   wire [31:0] 					w_rvcontrol, w_resume_pc;

   //inputs to axi slave
   wire [31:0] 					w_rvstatus, w_epc;
   wire [31:0]					w_states;
   

   wire [31:0] 					w_pc, w_pc2;
   wire 					w_pc_valid, w_pc2_valid;
   
   wire 					w_reset_out, 
						w_in_flush,
						w_ready, 
						w_got_break,
						w_got_ud,
						w_got_bad_addr,
						w_got_monitor,
						w_l1i_flushed,
						w_l1d_flushed,
						w_l2_flushed;
   wire [4:0] 					w_state;

   wire [63:0] 					w_l1i_cache_accesses;
   wire [63:0] 					w_l1i_cache_hits;
   wire [63:0] 					w_l1d_cache_accesses;
   wire [63:0] 					w_l1d_cache_hits;
   wire [63:0] 					w_l2_cache_accesses;
   wire [63:0] 					w_l2_cache_hits;

   wire [63:0]					w_txn_lat, w_txn_cnt;
   wire 					w_reset = (s00_axi_aresetn==1'b0);
   
   
   //connects to axi master
   wire 					w_mem_req_valid, w_mem_rsp_valid;
   wire						w_mem_req_gnt;
   wire [1:0]					w_mem_req_tag, w_mem_rsp_tag;
   wire [3:0]					w_mem_req_opcode;
   wire [127:0]					w_load_data;
   
   wire [3:0] w_dstate;
   wire [3:0] w_istate;
   wire [4:0] w_cstate, w_l2state;
   wire [3:0] w_axistate;
   wire	      w_memq_empty;
   
   wire 					w_putchar_fifo_empty;
   wire [7:0] 					w_putchar_fifo_out;
   wire 					w_putchar_fifo_pop;
   wire [3:0]					w_putchar_fifo_rptr, w_putchar_fifo_wptr;
   
   assign w_states = {
		      6'd0,
		      w_axistate,
		      w_dstate,
		      w_istate,
		      w_l2state,
		      w_cstate
		      };
   
   
   assign w_rvstatus = {1'd0,//w_l2state,
			w_memq_empty,
			2'd0,
			w_istate[2:0],
			w_mem_rsp_valid, 
			w_dstate, //4 bits
			w_mem_req_opcode, //4 bits
			w_mem_req_valid,
			w_reset_out,
			w_l2_flushed,//13
			w_l1i_flushed,//12
			w_l1d_flushed, //11
			w_state,//6
			w_got_monitor, //5
			w_got_bad_addr, //4
			w_got_ud, //3
			w_got_break, //2
			w_in_flush, //1
			w_ready}; //0

   reg [63:0]					r_bad_pc;   
   wire [31:0]					w_last_addr, w_last_data;
   
   // Instantiation of Axi Bus Interface S00_AXI
   axi_is_the_worst_v1_0_S00_AXI # ( 
				     .C_S_AXI_DATA_WIDTH(C_S00_AXI_DATA_WIDTH), 
				     .C_S_AXI_ADDR_WIDTH(C_S00_AXI_ADDR_WIDTH)) 
   axi_is_the_worst_v1_0_S00_AXI_inst (
				       .controlreg(w_controlreg),
				       .base(w_baseaddr),
				       .mask(w_addrmask),
				       .status(w_status),
				       .last_addr(w_last_addr),
				       .last_data(w_last_data),				       
				       .putchar_fifo_out(w_putchar_fifo_out),
				       .putchar_fifo_empty(w_putchar_fifo_empty),
				       .putchar_fifo_pop(w_putchar_fifo_pop),
				       .putchar_fifo_wptr(w_putchar_fifo_wptr),
				       .putchar_fifo_rptr(w_putchar_fifo_rptr),
				       .control(w_rvcontrol),
				       .resume_pc(w_resume_pc),
				       .rvstatus(w_rvstatus),
				       .states(w_states),
				       .epc(w_epc),
				       .rv_mem_addr(w_axi_addr),
				       .pc(w_pc),
				       .pc2(w_pc2),
				       .pc_valid(w_pc_valid),
				       .pc2_valid(w_pc2_valid),
				       .l1i_cache_accesses(w_l1i_cache_accesses),
				       .l1i_cache_hits(w_l1i_cache_hits),
				       .l1d_cache_accesses(w_l1d_cache_accesses),
				       .l1d_cache_hits(w_l1d_cache_hits),
				       .l2_cache_accesses(w_l2_cache_accesses),
				       .l2_cache_hits(w_l2_cache_hits),
				       .branch_faults('d0),

				       .dram_req_cnt(w_txn_cnt),
				       .dram_req_cycles(w_txn_lat),
				       .rv_reset(w_rvcontrol[0]),

				       .S_AXI_ACLK(s00_axi_aclk),
				       .S_AXI_ARESETN(s00_axi_aresetn),
				       .S_AXI_AWADDR(s00_axi_awaddr),
				       .S_AXI_AWPROT(s00_axi_awprot),
				       .S_AXI_AWVALID(s00_axi_awvalid),
				       .S_AXI_AWREADY(s00_axi_awready),
				       .S_AXI_WDATA(s00_axi_wdata),
				       .S_AXI_WSTRB(s00_axi_wstrb),
				       .S_AXI_WVALID(s00_axi_wvalid),
				       .S_AXI_WREADY(s00_axi_wready),
				       .S_AXI_BRESP(s00_axi_bresp),
				       .S_AXI_BVALID(s00_axi_bvalid),
				       .S_AXI_BREADY(s00_axi_bready),
				       .S_AXI_ARADDR(s00_axi_araddr),
				       .S_AXI_ARPROT(s00_axi_arprot),
				       .S_AXI_ARVALID(s00_axi_arvalid),
				       .S_AXI_ARREADY(s00_axi_arready),
				       .S_AXI_RDATA(s00_axi_rdata),
				       .S_AXI_RRESP(s00_axi_rresp),
				       .S_AXI_RVALID(s00_axi_rvalid),
				       .S_AXI_RREADY(s00_axi_rready)
				       );

   // Instantiation of Axi Bus Interface M00_AXI

   
   axi_is_the_worst_v1_0_M00_AXI # ( 
				     .C_M_TARGET_SLAVE_BASE_ADDR(0), 
				     .C_M_AXI_BURST_LEN(C_M00_AXI_BURST_LEN),
				     .C_M_AXI_ID_WIDTH(C_M00_AXI_ID_WIDTH), 
				     .C_M_AXI_ADDR_WIDTH(C_M00_AXI_ADDR_WIDTH),
				     .C_M_AXI_DATA_WIDTH(C_M00_AXI_DATA_WIDTH),
				     .C_M_AXI_AWUSER_WIDTH(C_M00_AXI_AWUSER_WIDTH),
				     .C_M_AXI_ARUSER_WIDTH(C_M00_AXI_ARUSER_WIDTH),
				     .C_M_AXI_WUSER_WIDTH(C_M00_AXI_WUSER_WIDTH),
				     .C_M_AXI_RUSER_WIDTH(C_M00_AXI_RUSER_WIDTH),
				     .C_M_AXI_BUSER_WIDTH(C_M00_AXI_BUSER_WIDTH)
				     )
   axi_is_the_worst_v1_0_M00_AXI_inst (
				       .rv_reset(w_rvcontrol[0]),
				       .step_txn(w_rvcontrol[16]),
				       .ack_txn(w_rvcontrol[31]),
				       .baseaddr(w_axi_addr),
				       .txn_lat(w_txn_lat),
				       .txn_cnt(t_txn_cnt),
				       .load_data(w_load_data),
				       .state(w_axistate),
				       .last_addr(w_last_addr),
				       .last_data(w_last_data),
				       .mem_req_store_data(w_mem_req_store_data),
				       
				       .mem_req_valid(w_mem_req_valid),
				       .mem_req_tag(w_mem_req_tag),
				       .mem_opcode(w_mem_req_opcode), 
				       .mem_rsp_valid(w_mem_rsp_valid),
				       .mem_rsp_tag(w_mem_rsp_tag),				       
				       .mem_req_gnt(w_mem_req_gnt),
				       .INIT_AXI_TXN(m00_axi_init_axi_txn),
				       .TXN_DONE(m00_axi_txn_done),
				       .ERROR(m00_axi_error),
				       .M_AXI_ACLK(m00_axi_aclk),
				       .M_AXI_ARESETN(m00_axi_aresetn),
				       .M_AXI_AWID(m00_axi_awid),
				       .M_AXI_AWADDR(m00_axi_awaddr),
				       .M_AXI_AWLEN(m00_axi_awlen),
				       .M_AXI_AWSIZE(m00_axi_awsize),
				       .M_AXI_AWBURST(m00_axi_awburst),
				       .M_AXI_AWLOCK(m00_axi_awlock),
				       .M_AXI_AWCACHE(m00_axi_awcache),
				       .M_AXI_AWPROT(m00_axi_awprot),
				       .M_AXI_AWQOS(m00_axi_awqos),
				       .M_AXI_AWUSER(m00_axi_awuser),
				       .M_AXI_AWVALID(m00_axi_awvalid),
				       .M_AXI_AWREADY(m00_axi_awready),
				       .M_AXI_WDATA(m00_axi_wdata),
				       .M_AXI_WSTRB(m00_axi_wstrb),
				       .M_AXI_WLAST(m00_axi_wlast),
				       .M_AXI_WUSER(m00_axi_wuser),
				       .M_AXI_WVALID(m00_axi_wvalid),
				       .M_AXI_WREADY(m00_axi_wready),
				       .M_AXI_BID(m00_axi_bid),
				       .M_AXI_BRESP(m00_axi_bresp),
				       .M_AXI_BUSER(m00_axi_buser),
				       .M_AXI_BVALID(m00_axi_bvalid),
				       .M_AXI_BREADY(m00_axi_bready),
				       .M_AXI_ARID(m00_axi_arid),
				       .M_AXI_ARADDR(m00_axi_araddr),
				       .M_AXI_ARLEN(m00_axi_arlen),
				       .M_AXI_ARSIZE(m00_axi_arsize),
				       .M_AXI_ARBURST(m00_axi_arburst),
				       .M_AXI_ARLOCK(m00_axi_arlock),
				       .M_AXI_ARCACHE(m00_axi_arcache),
				       .M_AXI_ARPROT(m00_axi_arprot),
				       .M_AXI_ARQOS(m00_axi_arqos),
				       .M_AXI_ARUSER(m00_axi_aruser),
				       .M_AXI_ARVALID(m00_axi_arvalid),
				       .M_AXI_ARREADY(m00_axi_arready),
				       .M_AXI_RID(m00_axi_rid),
				       .M_AXI_RDATA(m00_axi_rdata),
				       .M_AXI_RRESP(m00_axi_rresp),
				       .M_AXI_RLAST(m00_axi_rlast),
				       .M_AXI_RUSER(m00_axi_ruser),
				       .M_AXI_RVALID(m00_axi_rvalid),
				       .M_AXI_RREADY(m00_axi_rready)
				       );

   // Add user logic here



   assign w_l1i_flushed = 1'b0;
   assign w_l1d_flushed = 1'b0;
   assign w_l2_flushed = 1'b0;

   wire [1:0]					w_priv;
   wire						w_took_exc;
   reg [63:0]					r_last_retired_pc;


   always@(posedge s00_axi_aclk)
     begin
	if(w_reset | w_rvcontrol[0])
	  begin
	     r_bad_pc <= 64'd0;
	  end
	else if(w_took_exc)
	  begin
	     r_bad_pc <= r_last_retired_pc;
	  end
     end
   
   always@(posedge s00_axi_aclk)
     begin
	if(w_reset | w_rvcontrol[0])
	  begin
	     r_last_retired_pc <= 64'd0;
	  end
	else if(w_priv == 2'd0)
	  begin
	     if(w_pc2_valid)
	       begin
		  r_last_retired_pc <= w_pc2;
	       end
	     else if(w_pc_valid)
	       begin
		  r_last_retired_pc <= w_pc;		  
	       end
	  end // if (w_priv == 2'd0)
     end // always@ (posedge clk)
   
   
   core_l1d_l1i 
     cpu0 (
	   .clk(s00_axi_aclk),
	   .reset(w_reset | w_rvcontrol[0]),
	   .syscall_emu(1'b0),
	   //.reset_out(w_reset_out),
	   .core_state(w_cstate),
	   .l1d_state(w_dstate),
	   .l1i_state(w_istate),
	   .l2_state(w_l2state),		     
	   .memq_empty(w_memq_empty),
	   .putchar_fifo_out(w_putchar_fifo_out),
	   .putchar_fifo_empty(w_putchar_fifo_empty),
	   .putchar_fifo_pop(w_putchar_fifo_pop),		     
	   .putchar_fifo_wptr(w_putchar_fifo_wptr),
	   .putchar_fifo_rptr(w_putchar_fifo_rptr),
	   .extern_irq(1'b0),
	   .in_flush_mode(w_in_flush),
	   .resume(w_rvcontrol[1]),
	   .resume_pc(w_resume_pc),
	   .ready_for_resume(w_ready),
	   
	   .mem_req_valid(w_mem_req_valid),
	   .mem_req_tag(w_mem_req_tag),
	   .mem_req_addr(w_mem_req_addr),
	   .mem_req_store_data(w_mem_req_store_data),
	   .mem_req_opcode(w_mem_req_opcode),
	   .mem_req_gnt(w_mem_req_gnt),
	   .mem_rsp_tag(w_mem_rsp_tag),
	   .mem_rsp_valid(w_mem_rsp_valid),
	   .mem_rsp_load_data(w_load_data),		     
	   
	   .alloc_valid(),
	   .alloc_two_valid(),
	   .iq_one_valid(),
	   .iq_none_valid(),
	   .in_branch_recovery(),
	   .retire_reg_ptr(),
	   .retire_reg_data(),
	   .retire_reg_valid(),
	   .retire_reg_two_ptr(),
	   .retire_reg_two_data(),
	   .retire_reg_two_valid(),
	   .retire_valid(w_pc_valid),
	   .retire_two_valid(w_pc2_valid),
	   .retire_pc(w_pc),
	   .retire_two_pc(w_pc2),
	   .branch_pc(),
	   .branch_pc_valid(),
	   .branch_fault(),
	   .l1i_cache_accesses(w_l1i_cache_accesses),
	   .l1i_cache_hits(w_l1i_cache_hits),
	   .l1d_cache_accesses(w_l1d_cache_accesses),
	   .l1d_cache_hits(w_l1d_cache_hits),
	   .l2_cache_accesses(w_l2_cache_accesses),
	   .l2_cache_hits(w_l2_cache_hits),
	   
	   .monitor_ack(1'b0),
	   .got_break(w_got_break),
	   .got_ud(w_got_ud),
	   .got_bad_addr(w_got_bad_addr),
	   .got_monitor(w_got_monitor),
	   .inflight(),
	   .took_exc(w_took_exc),
	   .priv(w_priv),
	   .epc(w_epc)
	   );   

endmodule
