
// CaptureDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Capture.h"
#include "CaptureDlg.h"
#include "afxdialogex.h"
#include "pcap.h"


#ifdef _DEBUG
#define new DEBUG_NEW                                                         

#endif
#define WM_PACKET WM_USER+1
unsigned long cksum = 0;
//全局变量
pcap_t* afx_adhandle;         //当前打开的网络接口
struct pcap_pkthdr* afx_header;//截获帧头部
const u_char* afx_pkt_data;//截获帧数据

USHORT checksum(IPHeader_t head);
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:
//	afx_msg void OnPaint();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
//	ON_WM_PAINT()
END_MESSAGE_MAP()


// CCaptureDlg 对话框



CCaptureDlg::CCaptureDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_CAPTURE_DIALOG, pParent)
	, m_select(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_this_netmask = 0;
	//获得本机的设备列表
	char  errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&m_alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		MessageBox(L"获取本机设备列表失败：" + CString(errbuf), MB_OK);/*错误处理*/
	}
	m_now = m_alldevs;
}

void CCaptureDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CATCH, m_catch);
	DDX_Control(pDX, IDC_EDIT, mc_select);
	DDX_Text(pDX, IDC_EDIT, m_select);
	DDX_Control(pDX, IDC_Interface_LIST, mc_interface);
	DDX_Control(pDX, IDC_LIST, m_list);
	DDX_Control(pDX, IDC_Message_LIST, mc_message);
	DDX_Control(pDX, IDC_RETURN, m_return);
	DDX_Control(pDX, IDC_STOP, m_stop);
}

BEGIN_MESSAGE_MAP(CCaptureDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_LBN_SELCHANGE(IDC_Interface_LIST, &CCaptureDlg::OnSelchangeInterfaceList)
	ON_BN_CLICKED(IDC_CATCH, &CCaptureDlg::OnClickedCatch)
	ON_BN_CLICKED(IDC_STOP, &CCaptureDlg::OnClickedStop)
	ON_BN_CLICKED(IDC_RETURN, &CCaptureDlg::OnClickedReturn)
	ON_MESSAGE(WM_PACKET, &CCaptureDlg::OnPacket)
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CCaptureDlg 消息处理程序

BOOL CCaptureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	//获取本机接口和IP地址             
	pcap_if_t* d;		//指向设备链表首部的指针

	for (d = m_alldevs; d != NULL; d = d->next)      //显示接口列表
	{
		mc_interface.AddString(CString(d->name));	//利用d->name获取该网络接口设备的名字
	}

	Update_Message();//更新信息
	mc_interface.SetCurSel(0);
	m_stop.EnableWindow(FALSE);	//开始使“停止捕获”按钮失效
	m_return.EnableWindow(FALSE);	//开始使“返回”按钮失效


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CCaptureDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CCaptureDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CCaptureDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



// 线程函数的定义
UINT Capturer(LPVOID pParm)
{
	// TODO: 在此处添加实现代码.

	CCaptureDlg* dlg = (CCaptureDlg*)theApp.m_pMainWnd; //获取对话框句柄

	char errbuff[1000];
	memset(errbuff, 0, sizeof(errbuff));

	if ((afx_adhandle = pcap_open(dlg->m_now->name,	// 设备名称
		65536,	 // WinPcap获取网络数据包的最大长度
		PCAP_OPENFLAG_PROMISCUOUS,	// 混杂模式
		1000,	 // 读超时为1秒
		NULL,
		errbuff	// error buffer
	)) == NULL)
	{
		AfxMessageBox(L"打开该设备网卡接口失败!", MB_OK | MB_ICONERROR);
		return -1;
	}
	if (!dlg->m_select.IsEmpty())
	{
		struct bpf_program fcode;     //pcap_compile所调用的结构体
		//达式编译成能够被过滤引擎所解释的低层的字节码
		char str[20];
		memset(str, 0, sizeof(str));
		for (int i = 0; i < dlg->m_select.GetLength(); i++)
			str[i] = dlg->m_select[i];

		if (pcap_compile(afx_adhandle, &fcode, str, 1, dlg->m_this_netmask) < 0)
			AfxMessageBox(L"过滤出现问题!", MB_OK | MB_ICONERROR);
		if (pcap_setfilter(afx_adhandle, &fcode) < 0)
			AfxMessageBox(L"过滤出现问题!", MB_OK | MB_ICONERROR);
	}

	//利用pcap_next_ex函数捕获数据包
	/* 此处循环调用 pcap_next_ex来接受数据报*/
	int res;
	while (dlg->m_state && (res = pcap_next_ex(afx_adhandle, &afx_header, &afx_pkt_data)) >= 0) {
		if (res == 0)  //超时情况
			continue;
		//利用窗口的PostMessage函数发送消息
		AfxGetApp()->m_pMainWnd->PostMessage(WM_PACKET, 0, 0);
		//memset(afx_header,0,sizeof(afx_header));
		//memset(afx_pkt_data,0,sizeof(afx_pkt_data));
	}
	if (res == -1)  //获取数据包错误
	{
		AfxGetApp()->m_pMainWnd->PostMessage(WM_PACKET, 1, 1);
		dlg->m_state = false;
	}

	return 0;
}


// 更新捕获接口的详细信息框
void CCaptureDlg::Update_Message()
{
	// TODO: 在此处添加实现代码.
	//更新捕获接口的详细信息
	mc_message.ResetContent();//清除原有框的内容
	mc_message.AddString(CString(m_now->name));			//显示该网络接口设备的名字
	mc_message.AddString(CString(m_now->description));	//显示该网络接口设备的描述信息

	pcap_addr_t* a;
	a = m_now->addresses;
	for (a = m_now->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {  //判断该地址是否IP地址
			CString output;
			DWORD temp_IP;

			temp_IP = ntohl(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);  //显示IP地址
			output.Format(L"IP地址：%s", long2ip(temp_IP));
			mc_message.AddString(output);


			m_this_netmask = ntohl(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr);  //显示地址掩码
			output.Format(L"地址掩码：%s", long2ip(m_this_netmask));
			mc_message.AddString(output);


			temp_IP = ntohl(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr);  //显示广播地址
			output.Format(L"广播地址：%s", long2ip(temp_IP));
			mc_message.AddString(output);

		}
	}

}


// 将数字类型的IP地址转化为字符串类型
CString CCaptureDlg::long2ip(DWORD in)
{
	// TODO: 在此处添加实现代码.
	DWORD mask[] = { 0xFF000000,0x00FF0000,0x0000FF00,0x000000FF };
	DWORD num[4];

	num[0] = in & mask[0];
	num[0] = num[0] >> 24;

	num[1] = in & mask[1];
	num[1] = num[1] >> 16;

	num[2] = in & mask[2];
	num[2] = num[2] >> 8;

	num[3] = in & mask[3];

	CString ans;
	ans.Format(L"%03d.%03d.%03d.%03d", num[0], num[1], num[2], num[3]);
	return ans;
}


void CCaptureDlg::OnSelchangeInterfaceList()
{

	// TODO: 在此添加控件通知处理程序代码
	if (!m_state) {
		int N = mc_interface.GetCurSel();//获取listbox被选中的行的数目
		m_now = m_alldevs;
		while (N--)
		{
			m_now = m_now->next;
		}
		Update_Message();
	}
}


void CCaptureDlg::OnClickedCatch()
{
	// TODO: 在此添加控件通知处理程序代码
	m_state = true;	//将是否进入捕获状态标记打开
	mc_interface.EnableWindow(FALSE);
	mc_select.EnableWindow(FALSE);
	//调整按钮状态
	m_catch.EnableWindow(FALSE);
	m_stop.EnableWindow(TRUE);
	m_return.EnableWindow(FALSE);

	m_list.ResetContent();//清除原有框的内容

	//创建工作者线程
	m_capturer = AfxBeginThread((AFX_THREADPROC)Capturer, NULL, THREAD_PRIORITY_NORMAL);
	if (m_capturer == NULL) {
		AfxMessageBox(L"启动捕获数据包线程失败!", MB_OK | MB_ICONERROR);
		return;
	}
	else   /*打开选择的网卡 */
	{
		m_list.AddString(L"--------------------------------------------------------------------------------------------------------------------------------------------------------");
		m_list.AddString(L"监听" + CString(m_now->description) + L" 开始！");
		m_list.AddString(L"--------------------------------------------------------------------------------------------------------------------------------------------------------");
	}
	UpdateData(true);
}


void CCaptureDlg::OnClickedStop()
{
	//调整按钮状态
	m_catch.EnableWindow(TRUE);
	m_stop.EnableWindow(FALSE);
	m_return.EnableWindow(TRUE);
	mc_select.EnableWindow(TRUE);
	m_state = false;
	// TODO: 在此添加控件通知处理程序代码
}


void CCaptureDlg::OnClickedReturn()
{
	// TODO: 在此添加控件通知处理程序代码
	//调整按钮状态
	m_state = false;
	mc_interface.EnableWindow(TRUE);
	m_catch.EnableWindow(TRUE);
	m_stop.EnableWindow(FALSE);
	m_return.EnableWindow(FALSE);
	mc_select.EnableWindow(TRUE);
	m_list.ResetContent();//清除原有框的内容
	m_select = L"";
	UpdateData(false);
}


afx_msg LRESULT CCaptureDlg::OnPacket(WPARAM wParam, LPARAM lParam)
{
	/*……*/	//处理捕获到的数据包
	if (wParam == 0 && lParam == 0 && m_state == true)
	{

		//显示目的地址，源地址，帧类型	

		Data_t* IPPacket;
		ULONG		SourceIP, DestinationIP;
		IPPacket = (Data_t*)afx_pkt_data;
		SourceIP = ntohl(IPPacket->IPHeader.SrcIP);
		DestinationIP = ntohl(IPPacket->IPHeader.DstIP);

		WORD Kind = ntohs(IPPacket->FrameHeader.FrameType);
		WORD Len = afx_header->caplen;
		

		USHORT modify = checksum(IPPacket->IPHeader);

		time_t time = afx_header->ts.tv_sec;
		struct tm* ltime = new struct tm;
		localtime_s(ltime, &time);
		char timestr[16];
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		CString TIME(timestr);

		
		CString output1, output2, output3;
		//CString TIME=CTime::GetCurrentTime().Format("%H:%M:%S");
		output1.Format(L"%s , len: %d", TIME, Len);
		output2.Format(L"目的地址： %s     源地址： %s     帧类型：0x%04X", char2mac(IPPacket->FrameHeader.DesMAC), char2mac(IPPacket->FrameHeader.SrcMAC), Kind);
		output3.Format(L"标识： %04X     头部校验和： %04X     计算出的头部校验和：%04X",ntohs(IPPacket->IPHeader.ID), ntohs(IPPacket->IPHeader.Checksum),modify);

		//将光标设定在最后一行
		m_list.AddString(output1);
		m_list.AddString(output2);
		m_list.AddString(output3);
		int num = m_list.GetCount();
		m_list.SetCurSel(num - 1);
	}
	else
	{
		m_list.AddString(L"获取数据包结束！");
	}
	m_list.AddString(L"--------------------------------------------------------------------------------------------------------------------------------------------------------");
	return 0;
}


// 将char*类型的MAC地址转换成字符串类型
CString CCaptureDlg::char2mac(BYTE* MAC)
{

	// TODO: 在此处添加实现代码.
	CString ans;
	ans.Format(L"%02X-%02X-%02X-%02X-%02X-%02X", int(MAC[0]), int(MAC[1]), int(MAC[2]), int(MAC[3]), int(MAC[4]), int(MAC[5]));
	return ans;
}


void CCaptureDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	pcap_freealldevs(m_alldevs); //释放设备列表
	CDialogEx::OnClose();
}

USHORT checksum(IPHeader_t head)
{
	head.Checksum = 0;
	ULONG a = u_int8_t(head.SrcIP);
	ULONG b = head.DstIP;
	int size = head.TotalLen;
	USHORT hlen = head.Ver_HLen << 8;
	USHORT tos = head.TOS;
	USHORT tol = ntohs(head.TotalLen);
	USHORT id = ntohs(head.ID);
	USHORT seg = ntohs(head.Flag_Segment);
	USHORT ttl = head.TTL << 8;
	USHORT prot = head.Protocol;
	USHORT cks = head.Checksum;
	USHORT src[2];
	src[0] = ntohs(head.SrcIP >> 16);
	src[1] = ntohs(USHORT(head.SrcIP));
	USHORT dst[2];
	dst[0] = ntohs(head.DstIP >> 16);
	dst[1] = ntohs(USHORT(head.DstIP));
	USHORT buffer[12] = { hlen,tos,tol,id,seg,ttl,prot,cks,src[0],src[1],dst[0],dst[1] };

	int i = 0; cksum = 0;
	while (i < 12)
	{

		cksum += buffer[i];
		i++;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	return ~(USHORT(cksum));
}