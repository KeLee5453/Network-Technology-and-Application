
// CaptureDlg.h: 头文件
//

#pragma once
#include "pcap.h"

// CCaptureDlg 对话框
class CCaptureDlg : public CDialogEx
{
// 构造
public:
	CCaptureDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CAPTURE_DIALOG };
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
	pcap_if_t* m_alldevs;
	pcap_if_t* m_now;
	bool m_state;
	CWinThread* m_capturer;
	DWORD m_this_netmask;
	CButton m_catch;
	CEdit mc_select;
	CString m_select;
	CListBox mc_interface;
	CListBox m_list;
	CListBox mc_message;
	CButton m_return;
	CButton m_stop;
	// 更新捕获接口的详细信息框
	void Update_Message();
	// 将数字类型的IP地址转化为字符串类型
	CString long2ip(DWORD in);

	afx_msg void OnSelchangeInterfaceList();
	afx_msg void OnClickedCatch();
	afx_msg void OnClickedStop();
	afx_msg void OnClickedReturn();
protected:
	afx_msg LRESULT OnPacket(WPARAM wParam, LPARAM lParam);
public:
	// 将char*类型的MAC地址转换成字符串类型
	CString char2mac(BYTE* MAC);
	afx_msg void OnClose();
};

#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t {	//帧首部
	BYTE	DesMAC[6];	// 目的地址
	BYTE 	SrcMAC[6];	// 源地址
	WORD	FrameType;	// 帧类型
} FrameHeader_t;
typedef struct IPHeader_t {		//IP首部
	BYTE	Ver_HLen;
	BYTE	TOS;
	WORD	TotalLen;
	WORD	ID;
	WORD	Flag_Segment;
	BYTE	TTL;
	BYTE	Protocol;
	WORD	Checksum;
	ULONG	SrcIP;
	ULONG	DstIP;
} IPHeader_t;
typedef struct Data_t {	//包含帧首部和IP首部的数据包
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//恢复缺省对齐方式