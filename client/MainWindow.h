/*
 * QDigiDocClient
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#pragma once

#include "ui_MainWindow.h"

#include "DigiDoc.h"

#include <QtCore/QStringList>
#include <QtWidgets/QProgressDialog>

#include <memory>

class DigiDoc;
class QPrinter;

class MainWindow: public QWidget, private Ui::MainWindow
{
	Q_OBJECT

public:
	explicit MainWindow( QWidget *parent = 0 );

	void closeDoc();

private Q_SLOTS:
	void activateProgressDlg( const QString &fileName, const QString &title, bool cancellable );
	void added( int taskId, bool success );
	void buttonClicked( int button );
	void cancelOperation();
	void changeCard( QAction *a );
	void changeLang( QAction *a );
	void closeProgress();
	void enableSign();
	void messageClicked( const QString &link );
	void on_introCheck_stateChanged( int state );
	void on_languages_activated( int index );
	void open( const QStringList &params );
	void opened( int taskId, bool success );
	void parseLink( const QString &link );
	void printSheet( QPrinter * );
	void saved( int taskId, bool success );
	void setProgress( int value );
	void showCardStatus();
	void verifyExternally();
	void viewSignaturesRemove( unsigned int num );

private:
	enum Pages {
		Home,
		Intro,
		Sign,
		View
	};
	enum Buttons {
		HeadAbout,
		HeadSettings,
		HeadHelp,
		HomeCrypt,
		HomeSign,
		IntroBack,
		IntroAgree,
		SignCancel,
		SignSign,
		SignAdd,
		HomeView,
		ViewAddSignature,
		ViewClose,
		ViewBrowse,
		ViewEmail,
		ViewPrint,
		ViewEncrypt,
		ViewSaveAs,
		ViewSaveFiles
	};
	bool addFile( const QString &file );
	void enableSign( int warning );
	bool event( QEvent *e );
	void loadRoles();
	void retranslate();
	void save( DigiDoc::SaveAction action );
	QString selectFile( const QString &filename, bool fixedExt );
	void setCurrentPage( Pages page, QList<DigiDocSignature::SignatureStatus> *validatedSignatures = nullptr );
	void showWarning( const QString &text );

	QActionGroup *cardsGroup;
	DigiDoc	*doc;
	QStringList lang, params;
	bool quitOnClose;
	int prevpage;
	QLabel *message;
	bool warnOnUnsignedDocCancel;
	std::shared_ptr<QProgressDialog> progressDlg;

Q_SIGNALS:
	void progressFinished();

};
