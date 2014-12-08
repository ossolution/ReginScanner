# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui/untitled.ui'
#
# Created: Mon Dec  8 14:29:51 2014
#      by: PyQt4 UI code generator 4.10.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui
import resource_rc

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        # Main Window
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.setEnabled(True)
        MainWindow.resize(634, 548)

        # Icon
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/img/logo.ico")), QtGui.QIcon.Normal, QtGui.QIcon.On)

        # Main Window Attr
        MainWindow.setWindowIcon(icon)
        MainWindow.setToolTip(_fromUtf8(""))
        MainWindow.setLayoutDirection(QtCore.Qt.RightToLeft)
        MainWindow.setAutoFillBackground(True)
        MainWindow.setLocale(QtCore.QLocale(QtCore.QLocale.Persian, QtCore.QLocale.Iran))
        MainWindow.setIconSize(QtCore.QSize(50, 50))
        MainWindow.setToolButtonStyle(QtCore.Qt.ToolButtonIconOnly)

        # Centeral
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))

        # Main Frame
        self.MainFrame = QtGui.QFrame(self.centralwidget)
        self.MainFrame.setGeometry(QtCore.QRect(6, 6, 621, 481))
        self.MainFrame.setLayoutDirection(QtCore.Qt.RightToLeft)
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
        self.MainFrame.setFrameShape(QtGui.QFrame.StyledPanel)
        self.MainFrame.setFrameShadow(QtGui.QFrame.Raised)
        self.MainFrame.setObjectName(_fromUtf8("MainFrame"))

        # scan_progressBar
        self.scan_progressBar = QtGui.QProgressBar(self.MainFrame)
        self.scan_progressBar.setGeometry(QtCore.QRect(150, 40, 461, 31))
        self.scan_progressBar.setStyleSheet(_fromUtf8("QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.scan_progressBar.setProperty("value", 0)
        self.scan_progressBar.setObjectName(_fromUtf8("scan_progressBar"))

        
        # self.Logo = QtGui.QLabel(self.MainFrame)
        # self.Logo.setGeometry(QtCore.QRect(641, 73, 131, 171))
        # self.Logo.setObjectName(_fromUtf8("Logo"))
        self.AboutPush = QtGui.QPushButton(self.MainFrame)
        self.AboutPush.setGeometry(QtCore.QRect(631, 46, 141, 211))
        self.AboutPush.setStyleSheet(_fromUtf8("QPushButton {\n"
"padding: 50px 50 50 0;\n"
"background-image: url(:/image/image/ok.png);\n"
"background-repeat:no-repeat;\n"
"background-attachment:fixed;\n"
"background-position:center; \n"
"     border-style: outset;\n"
"     border-width: 0px;\n"
"     border-radius: 10px;\n"
"}"))
        self.AboutPush.setText(_fromUtf8(""))
        self.AboutPush.setObjectName(_fromUtf8("AboutPush"))
        self.TextFrame = QtGui.QFrame(self.MainFrame)
        self.TextFrame.setGeometry(QtCore.QRect(130, 76, 481, 281))
        self.TextFrame.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.TextFrame.setStyleSheet(_fromUtf8("#TextFrame {\n"
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
        self.TextFrame.setFrameShape(QtGui.QFrame.StyledPanel)
        self.TextFrame.setFrameShadow(QtGui.QFrame.Raised)
        self.TextFrame.setObjectName(_fromUtf8("TextFrame"))

        self.listView = QtGui.QListView(self.MainFrame)
        self.listView.setGeometry(QtCore.QRect(142, 88, 460, 261))
        self.listView.setStyleSheet(_fromUtf8("#listView\n"
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
        self.listView.setObjectName(_fromUtf8("listView"))


        self.Logo_2 = QtGui.QLabel(self.MainFrame)
        self.Logo_2.setGeometry(QtCore.QRect(21, 286, 201, 291))
        self.Logo_2.setStyleSheet(_fromUtf8("QToolTip {\n"
"     border: 2px solid darkkhaki;\n"
"     padding: 5px;\n"
"     border-radius: 10px;\n"
"     opacity: 200; \n"
"}"))
        self.Logo_2.setObjectName(_fromUtf8("Logo_2"))
        self.commandLinkButton = QtGui.QCommandLinkButton(self.MainFrame)
        self.commandLinkButton.setGeometry(QtCore.QRect(0, 180, 131, 41))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("B Lotus"))
        font.setPointSize(18)
        self.commandLinkButton.setFont(font)
        self.commandLinkButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.commandLinkButton.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.commandLinkButton.setAutoFillBackground(False)
        self.commandLinkButton.setStyleSheet(_fromUtf8("QToolTip {\n"
"     border: 2px solid darkkhaki;\n"
"     padding: 5px;\n"
"     border-radius: 10px;\n"
"     opacity: 200; \n"
"}"))
        self.commandLinkButton.setObjectName(_fromUtf8("commandLinkButton"))
        self.Logo_3 = QtGui.QLabel(self.MainFrame)
        self.Logo_3.setGeometry(QtCore.QRect(480, 280, 221, 281))
        self.Logo_3.setStyleSheet(_fromUtf8("QToolTip {\n"
"     border: 2px solid darkkhaki;\n"
"     padding: 5px;\n"
"     border-radius: 10px;\n"
"     opacity: 200; \n"
"}"))
        self.Logo_3.setObjectName(_fromUtf8("Logo_3"))
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 634, 25))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "ReginScanner", None))
        MainWindow.setStatusTip(_translate("MainWindow", "نرم افزار اسکن بدافزار رجین. تهیه شده توسط شرکت پیشکامان متن‌باز.", None))
        self.listView.setToolTip(_translate("MainWindow", "نمایش وضعیت بررسی فایل‌ها", None))
        self.MainFrame.setStatusTip(_translate("MainWindow", "نرم افزار اسکن بدافزار رجین. تهیه شده توسط شرکت پیشکامان متن‌باز.", None))
        # self.Logo.setText(_translate("MainWindow", "<html><head/><body><p><img src=\":/image/image/10649.png\"/></p></body></html>", None))
        self.AboutPush.setToolTip(_translate("MainWindow", "درباره‌ی من و نگار!", None))
        self.AboutPush.setStatusTip(_translate("MainWindow", "درباره‌ی من و نگار!", None))
        self.Logo_2.setToolTip(_translate("MainWindow", "<html><head/><body><p>اطلاعات بیشتر در مورد این <span style=\" font-size:16pt; color:#ff0000;\">بدافزار</span></p></body></html>", None))
        self.Logo_2.setText(_translate("MainWindow", "<html><head/><body><p><a href=\'http://regin.webcare.ir\'><img src=\":/img/logo.png\"/></a></p></body></html>", None))
        self.commandLinkButton.setToolTip(_translate("MainWindow", "شروع اسکن فایل ها", None))
        self.commandLinkButton.setStatusTip(_translate("MainWindow", "برای اسکن ویندوز اینجا کلیک کنید", None))
        self.commandLinkButton.setWhatsThis(_translate("MainWindow", "شروع اسکن", None))
        self.commandLinkButton.setText(_translate("MainWindow", "شروع اسکن", None))
        self.Logo_3.setToolTip(_translate("MainWindow", "مشاهده و دریافت کد برنامه", None))
        self.Logo_3.setText(_translate("MainWindow", "<html><head/><body><p><a href=\"https://github.com/ossolution/ReginScanner\"><img src=\":/img/github_icon.png\"/></a></p></body></html>", None))

