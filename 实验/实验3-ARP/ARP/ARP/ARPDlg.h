
// ARPDlg.h: 头文件
//
#include"pcap.h"

#pragma once


// CARPDlg 对话框
class CARPDlg : public CDialogEx
{
// 构造
public:
	CARPDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ARP_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListBox mc_Message;
	CListBox mc_list;
	pcap_if_t* m_alldevs;		//指向设备列表首部的指针	
	pcap_if_t* m_selectdevs;	//当前选择的设备列表的指针	
	DWORD m_this_ip;		//本机IP地址
	BYTE  m_this_mac[6];	//本机物理地址
	DWORD m_IP;				//查询的IP地址
	BYTE  m_MAC[6];			//查询获得的物理地址
	DWORD m_this_broad;		//本机广播地址
	DWORD m_this_netmask;	//本机子网掩码

	CWinThread* m_Capturer;		/*工作者线程*/
	bool  m_if_get_this_mac;		//标记是否已经获得本机MAC地址
	bool  m_get_state;				//标记是否已经获得请求的MAC地址
	DWORD ip2long(CString in);
//	CSring long2ip(DWORD in);
	CString long2ip(DWORD in);
	int GetSelfMac();/*获取自己主机的MAC地址*/
	int SendARP(BYTE* SrcMAC, BYTE* SendHa, DWORD SendIp, DWORD RecvIp);//发送ARP请求函数
																		// 将char*类型的MAC地址转换为字符串类型
	CString char2mac(BYTE* MAC);
	CButton mc_get;
	CButton mc_return;
	afx_msg void OnClose();
	afx_msg void OnFieldchangedIpaddress1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnClickedGet();
	afx_msg void OnClickedReturen();
};
//全局函数
UINT Capturer(LPVOID pParm);//线程函数的定义

#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t {	//帧首部
	BYTE	DesMAC[6];		// 目的地址
	BYTE	SrcMAC[6];		// 源地址
	WORD	FrameType;		// 帧类型
} FrameHeader_t;
typedef struct ARPFrame_t {		//ARP帧
	FrameHeader_t	FrameHeader;	//帧头部结构体
	WORD			HardwareType;	//硬件类型
	WORD			ProtocolType;	//协议类型
	BYTE			HLen;			//硬件地址长度
	BYTE			PLen;			//协议地址长度
	WORD			Operation;		//操作字段
	BYTE			SendHa[6];		//源mac地址
	DWORD			SendIP;			//源ip地址
	BYTE			RecvHa[6];		//目的mac地址
	DWORD			RecvIP;			//目的ip地址
} ARPFrame_t;
#pragma pack()		//恢复缺省对齐方式