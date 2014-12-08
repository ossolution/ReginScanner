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

        # Log Frame
        self.LogFrame = QtGui.QFrame(self.MainFrame)
        self.LogFrame.setGeometry(QtCore.QRect(130, 76, 481, 281))
        self.LogFrame.setLayoutDirection(QtCore.Qt.RightToLeft)
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
        self.LogFrame.setFrameShape(QtGui.QFrame.StyledPanel)
        self.LogFrame.setFrameShadow(QtGui.QFrame.Raised)
        self.LogFrame.setObjectName(_fromUtf8("LogFrame"))

        # Checked File List
        self.checkedFiles = QtGui.QListView(self.MainFrame)
        self.checkedFiles.setGeometry(QtCore.QRect(142, 88, 460, 261))
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

        # POS logo
        self.Pos_logo = QtGui.QLabel(self.MainFrame)
        self.Pos_logo.setGeometry(QtCore.QRect(21, 286, 201, 291))
        self.Pos_logo.setStyleSheet(_fromUtf8("QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.Pos_logo.setObjectName(_fromUtf8("Pos_logo"))

        # Run Scanner
        self.RunScanner = QtGui.QCommandLinkButton(self.MainFrame)
        self.RunScanner.setGeometry(QtCore.QRect(0, 180, 131, 41))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("B Lotus"))
        font.setPointSize(18)
        self.RunScanner.setFont(font)
        self.RunScanner.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.RunScanner.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.RunScanner.setAutoFillBackground(False)
        self.RunScanner.setStyleSheet(_fromUtf8("QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.RunScanner.setObjectName(_fromUtf8("commandLinkButton"))

        # GitHub Logo
        self.GitHub_logo = QtGui.QLabel(self.MainFrame)
        self.GitHub_logo.setGeometry(QtCore.QRect(480, 280, 221, 281))
        self.GitHub_logo.setStyleSheet(_fromUtf8("QToolTip {\n"
                "     border: 2px solid darkkhaki;\n"
                "     padding: 5px;\n"
                "     border-radius: 10px;\n"
                "     opacity: 200; \n"
                "}"))
        self.GitHub_logo.setObjectName(_fromUtf8("GitHub_logo"))

        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "ReginScanner", None))
        MainWindow.setStatusTip(_translate("MainWindow", "نرم افزار اسکن بدافزار رجین. تهیه شده توسط شرکت پیشکامان متن‌باز.", None))
        self.checkedFiles.setToolTip(_translate("MainWindow", "نمایش وضعیت بررسی فایل‌ها", None))
        self.MainFrame.setStatusTip(_translate("MainWindow", "نرم افزار اسکن بدافزار رجین. تهیه شده توسط شرکت پیشکامان متن‌باز.", None))
        self.Pos_logo.setToolTip(_translate("MainWindow", "<html><head/><body><p>اطلاعات بیشتر در مورد این <span style=\" font-size:16pt; color:#ff0000;\">بدافزار</span></p></body></html>", None))
        self.Pos_logo.setText(_translate("MainWindow", "<html><head/><body><p><a href=\'http://regin.webcare.ir\'><img src=\":/img/logo.png\"/></a></p></body></html>", None))
        self.RunScanner.setToolTip(_translate("MainWindow", "شروع اسکن فایل ها", None))
        self.RunScanner.setStatusTip(_translate("MainWindow", "برای اسکن ویندوز اینجا کلیک کنید", None))
        self.RunScanner.setWhatsThis(_translate("MainWindow", "شروع اسکن", None))
        self.RunScanner.setText(_translate("MainWindow", "شروع اسکن", None))
        self.GitHub_logo.setToolTip(_translate("MainWindow", "مشاهده و دریافت کد برنامه", None))
        self.GitHub_logo.setText(_translate("MainWindow", "<html><head/><body><p><a href=\"https://github.com/ossolution/ReginScanner\"><img src=\":/img/github_icon.png\"/></a></p></body></html>", None))

