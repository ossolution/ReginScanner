# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui/untitled.ui'
#
# Created: Mon Dec  8 14:29:51 2014
#      by: PyQt4 UI code generator 4.10.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4.QtCore import QString, QLocale, Qt, QSize, QRect, QMetaObject
from PyQt4.QtGui import QApplication, QLabel, QIcon, QPixmap, QWidget, QFrame, QProgressBar, QTextEdit, QCommandLinkButton, QFont, QCursor, QStatusBar
import resource_rc
import webbrowser
import urllib2

try:
    _fromUtf8 = QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
		# Hit URL
        try:
			response = urllib2.urlopen('http://regin.syscare.ir/Tester')
        except:
			pass
		
        # Main Window
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.setEnabled(True)
        MainWindow.setFixedSize(634, 548)

        # Icon
        icon = QIcon()
        icon.addPixmap(QPixmap(_fromUtf8(":/img/logo.png")), QIcon.Normal, QIcon.On)

		# FONT
        # Set up font:
		# TODO
        '''
        self.fontDB = QFontDatabase()
        self.fontDB.addApplicationFont(":/fonts/DroidNaskh-Regular.ttf")
        for item in QFontDatabase().families():
			try:
				if item == 'Droid Arabic Naskh':
					self.font=QFont(str(item),12)
			except:
				pass
        '''
        # Main Window Attr
        MainWindow.setWindowIcon(icon)
        MainWindow.setToolTip(_fromUtf8(""))
        MainWindow.setLayoutDirection(Qt.RightToLeft)
        MainWindow.setAutoFillBackground(True)
        MainWindow.setLocale(QLocale(QLocale.Persian, QLocale.Iran))
        MainWindow.setIconSize(QSize(50, 50))
        MainWindow.setToolButtonStyle(Qt.ToolButtonIconOnly)

        # Centeral
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))

        # Main Frame
        self.MainFrame = QFrame(self.centralwidget)
        self.MainFrame.setGeometry(QRect(6, 6, 621, 481))
        self.MainFrame.setLayoutDirection(Qt.RightToLeft)
        self.MainFrame.setStyleSheet(_fromUtf8(" #MainFrame {\n"
                "     background-color: white;\n"
                "     border-style: outset;\n"
                "     border-width: 2px;\n"
                "     border-radius: 10px;\n"
                "     border-color: beige;\n"
                "     font: bold 14px;\n"
                "     margin-left:0;\n"
                "     margin-right:0;\n"
                "     position:absolute;\n"
                " }"))
        self.MainFrame.setFrameShape(QFrame.StyledPanel)
        self.MainFrame.setFrameShadow(QFrame.Raised)
        self.MainFrame.setObjectName(_fromUtf8("MainFrame"))

        # scan_progressBar
        self.scan_progressBar = QProgressBar(self.MainFrame)
        self.scan_progressBar.setGeometry(QRect(150, 40, 461, 31))
        self.scan_progressBar.setStyleSheet(_fromUtf8("QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.scan_progressBar.setProperty("value", 0)
        self.scan_progressBar.setObjectName(_fromUtf8("scan_progressBar"))

        # Log Frame
        self.LogFrame = QFrame(self.MainFrame)
        self.LogFrame.setGeometry(QRect(130, 76, 481, 281))
        self.LogFrame.setLayoutDirection(Qt.RightToLeft)
        self.LogFrame.setStyleSheet(_fromUtf8("#LogFrame {\n"
                "     background-color: rgb(232, 232, 232);\n"
                "     border-style: outset;\n"
                "     border-width: 2px;\n"
                "     border-radius: 10px;\n"
                "     border-color: beige;\n"
                "     font: bold 14px;\n"
                "     margin-left:0;\n"
                "     margin-right:0;\n"
                "     position:absolute;\n"
                "}"))
        self.LogFrame.setFrameShape(QFrame.StyledPanel)
        self.LogFrame.setFrameShadow(QFrame.Raised)
        self.LogFrame.setObjectName(_fromUtf8("LogFrame"))

        # Checked File List
        self.checkedFiles = QTextEdit(self.MainFrame)
        self.checkedFiles.setGeometry(QRect(142, 88, 460, 261))
        self.checkedFiles.setStyleSheet(_fromUtf8("#checkedFiles\n"
                " {\n"
                "     border-style: outset;\n"
                "     border-width: 2px;\n"
                "     border-radius: 10px;\n"
                "     border-color: beige;\n"
                "     font: bold 14px;\n"
                "     margin-left:0;\n"
                "     margin-right:0;\n"
                "     position:absolute;\n"
                "}\n"
                "\n"
                "QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.checkedFiles.setObjectName(_fromUtf8("checkedFiles"))
        self.checkedFiles.setReadOnly(True)

        # POS logo
        self.Pos_logo = LinkLabel('http://regin.syscare.ir/', self.MainFrame)
        self.Pos_logo.setGeometry(QRect(21, 286, 201, 291))
        self.Pos_logo.setStyleSheet(_fromUtf8("QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.Pos_logo.setObjectName(_fromUtf8("Pos_logo"))

        # Run Scanner
        self.RunScanner = QCommandLinkButton(self.MainFrame)
        self.RunScanner.setGeometry(QRect(0, 180, 131, 41))
        font = QFont()
        font.setFamily("B Lotus")
        font.setPointSize(14)
        self.RunScanner.setFont(font)
        self.RunScanner.setCursor(QCursor(Qt.PointingHandCursor))
        self.RunScanner.setLayoutDirection(Qt.RightToLeft)
        self.RunScanner.setAutoFillBackground(False)
        self.RunScanner.setStyleSheet(_fromUtf8("QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.RunScanner.setObjectName(_fromUtf8("commandLinkButton"))

        # GitHub Logo
        self.GitHub_logo = LinkLabel('https://github.com/ossolution/ReginScanner', self.MainFrame)
        self.GitHub_logo.setGeometry(QRect(480, 280, 221, 281))
        self.GitHub_logo.setStyleSheet(_fromUtf8("QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.GitHub_logo.setObjectName(_fromUtf8("GitHub_logo"))

        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "ReginScanner", None))
        MainWindow.setStatusTip(_translate("MainWindow", "نرم افزار اسکن بدافزار رجین. تهیه شده توسط شرکت پیشکامان متن‌باز.", None))
        #self.checkedFiles.setToolTip(_translate("MainWindow", "نمایش وضعیت بررسی فایل‌ها", None))
        self.MainFrame.setStatusTip(_translate("MainWindow", "نرم افزار اسکن بدافزار رجین. تهیه شده توسط شرکت پیشکامان متن‌باز.", None))
        #self.Pos_logo.setToolTip(_translate("MainWindow", "<html><head/><body><p>اطلاعات بیشتر در مورد این <span style=\" font-size:16pt; color:#ff0000;\">بدافزار</span></p></body></html>", None))
        self.Pos_logo.setText(_translate("MainWindow", "<html><head/><body><p><a href=\'http://regin.syscare.ir\'><img src=\":/img/logo.png\"/></a></p></body></html>", None))
        #self.RunScanner.setToolTip(_translate("MainWindow", "شروع اسکن فایل ها", None))
        self.RunScanner.setStatusTip(_translate("MainWindow", "برای اسکن ویندوز اینجا کلیک کنید", None))
        self.RunScanner.setWhatsThis(_translate("MainWindow", "شروع اسکن", None))
        self.RunScanner.setText(_translate("MainWindow", "شروع اسکن", None))
        #self.GitHub_logo.setToolTip(_translate("MainWindow", "مشاهده و دریافت کد برنامه", None))
        self.GitHub_logo.setText(_translate("MainWindow", "<html><head/><body><p><a href=\"https://github.com/ossolution/ReginScanner\"><img src=\":/img/github_icon.png\"/></a></p></body></html>", None))

class LinkLabel(QLabel):
	url = ''
	def __init__(self, url, parent=None):
		super(LinkLabel, self).__init__(parent)
		self.url = url
		
	def mouseReleaseEvent(self,event):    		
		webbrowser.open(self.url)
		
