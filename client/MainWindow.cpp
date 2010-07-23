/*
 * QDigiDocClient
 *
 * Copyright (C) 2009 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009 Raul Metsma <raul@innovaatik.ee>
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

#include "MainWindow.h"

#include "common/CheckConnection.h"
#include "common/Common.h"
#include "common/IKValidator.h"
#include "common/Settings.h"
#include "common/SslCertificate.h"

#include "AccessCert.h"
#include "MobileDialog.h"
#include "PrintSheet.h"
#include "SettingsDialog.h"
#include "SignatureDialog.h"

#include <digidocpp/Document.h>

#include <QApplication>
#include <QDesktopServices>
#include <QDragEnterEvent>
#include <QFileDialog>
#include <QMessageBox>
#include <QPrintPreviewDialog>
#include <QTextStream>
#include <QTranslator>
#include <QUrl>

#if defined(Q_OS_MAC)
#include <QMenu>
#include <QMenuBar>
#endif

MainWindow::MainWindow( QWidget *parent )
:	QWidget( parent )
,	cardsGroup( new QActionGroup( this ) )
,	m_loaded( false )
,	quitOnClose( false )
{
	qRegisterMetaType<QSslCertificate>("QSslCertificate");

	setupUi( this );

	cards->hide();
	cards->hack();
	languages->hack();

	setWindowFlags( Qt::Window | Qt::CustomizeWindowHint | Qt::WindowMinimizeButtonHint );
#if QT_VERSION >= 0x040500
	setWindowFlags( windowFlags() | Qt::WindowCloseButtonHint );
#else
	setWindowFlags( windowFlags() | Qt::WindowSystemMenuHint );
#endif

	QApplication::instance()->installEventFilter( this );

	Common *common = new Common( this );
	QDesktopServices::setUrlHandler( "browse", common, "browse" );
	QDesktopServices::setUrlHandler( "mailto", common, "mailTo" );

	Settings s;
	// Mobile
#ifndef Q_OS_WIN32
#warning revert before release
#endif
	//disabled for testing
	//infoMobileCode->setValidator( new IKValidator( infoMobileCode ) );
	infoMobileCode->setText( s.value( "Client/MobileCode" ).toString() );
	infoMobileCell->setText( s.value( "Client/MobileNumber", "+372" ).toString() );
	connect( infoMobileCode, SIGNAL(textEdited(QString)), SLOT(enableSign()) );
	connect( infoMobileCell, SIGNAL(textEdited(QString)), SLOT(enableSign()) );
	connect( infoSignMobile, SIGNAL(toggled(bool)), SLOT(showCardStatus()) );

	// Buttons
	QButtonGroup *buttonGroup = new QButtonGroup( this );

	buttonGroup->addButton( settings, HeadSettings );
	buttonGroup->addButton( help, HeadHelp );

	buttonGroup->addButton( homeSign, HomeSign );
	buttonGroup->addButton( homeView, HomeView );
	buttonGroup->addButton( homeCrypt, HomeCrypt );

	introNext = introButtons->addButton( tr( "Next" ), QDialogButtonBox::ActionRole );
	buttonGroup->addButton( introNext, IntroNext );
	buttonGroup->addButton( introButtons->button( QDialogButtonBox::Cancel ), IntroBack );

	signButton = signButtons->addButton( tr("Sign"), QDialogButtonBox::AcceptRole );
	buttonGroup->addButton( signButton, SignSign );
	buttonGroup->addButton( signButtons->button( QDialogButtonBox::Cancel ), SignCancel );

	viewAddSignature = viewButtons->addButton( tr("Add signature"), QDialogButtonBox::ActionRole );
	buttonGroup->addButton( viewAddSignature, ViewAddSignature );
	buttonGroup->addButton( viewButtons->button( QDialogButtonBox::Close ), ViewClose );
	connect( buttonGroup, SIGNAL(buttonClicked(int)),
		SLOT(buttonClicked(int)) );

	connect( infoCard, SIGNAL(linkActivated(QString)), SLOT(parseLink(QString)) );

	// Digidoc
	doc = new DigiDoc( this );
	connect( cards, SIGNAL(activated(QString)), doc, SLOT(selectCard(QString)) );
	connect( doc, SIGNAL(error(QString)), SLOT(showWarning(QString)) );
	connect( doc, SIGNAL(dataChanged()), SLOT(showCardStatus()) );
	m_loaded = doc->init();

	// Translations
	appTranslator = new QTranslator( this );
	commonTranslator = new QTranslator( this );
	qtTranslator = new QTranslator( this );
	QApplication::instance()->installTranslator( appTranslator );
	QApplication::instance()->installTranslator( commonTranslator );
	QApplication::instance()->installTranslator( qtTranslator );
	lang << "et" << "en" << "ru";
	QString deflang;
	switch( QLocale().language() )
	{
	case QLocale::English: deflang = "en"; break;
	case QLocale::Russian: deflang = "ru"; break;
	case QLocale::Estonian:
	default: deflang = "et"; break;
	}
	on_languages_activated( lang.indexOf(
		s.value( "Main/Language", deflang ).toString() ) );
	QActionGroup *langGroup = new QActionGroup( this );
	QAction *etAction = langGroup->addAction( new QAction( langGroup ) );
	QAction *enAction = langGroup->addAction( new QAction( langGroup ) );
	QAction *ruAction = langGroup->addAction( new QAction( langGroup ) );
	etAction->setData( 0 );
	enAction->setData( 1 );
	ruAction->setData( 2 );
	etAction->setShortcut( Qt::CTRL + Qt::SHIFT + Qt::Key_1 );
	enAction->setShortcut( Qt::CTRL + Qt::SHIFT + Qt::Key_2 );
	ruAction->setShortcut( Qt::CTRL + Qt::SHIFT + Qt::Key_3 );
	addAction( etAction );
	addAction( enAction );
	addAction( ruAction );
	connect( langGroup, SIGNAL(triggered(QAction*)), SLOT(changeLang(QAction*)) );
	connect( cardsGroup, SIGNAL(triggered(QAction*)), SLOT(changeCard(QAction*)) );

	// Views
	signContentView->setColumnHidden( 2, true );
	viewContentView->setColumnHidden( 3, true );
	connect( signContentView, SIGNAL(remove(unsigned int)),
		SLOT(removeDocument(unsigned int)) );
	connect( viewContentView, SIGNAL(remove(unsigned int)),
		SLOT(removeDocument(unsigned int)) );

	// Actions
	closeAction = new QAction( tr("Close"), this );
	closeAction->setShortcut( Qt::CTRL + Qt::Key_W );
	connect( closeAction, SIGNAL(triggered()), this, SLOT(closeDoc()) );
	addAction( closeAction );
#if defined(Q_OS_MAC)
	QMenuBar *bar = new QMenuBar;
	QMenu *menu = bar->addMenu( tr("&File") );
	QAction *pref = menu->addAction( tr("Settings"), this, SLOT(showSettings()) );
	pref->setMenuRole( QAction::PreferencesRole );
	menu->addAction( closeAction );
#endif

	// Arguments
	QStringList args = qApp->arguments();
	if( args.size() > 1 )
	{
		quitOnClose = true;
		args.removeAt( 0 );
		params = args;
		buttonClicked( HomeSign );
	}
}

bool MainWindow::addFile( const QString &file )
{
	if( doc->isNull() )
	{
		Settings s;
		s.beginGroup( "Client" );
		QFileInfo info( file );
		QString docname = QString( "%1/%2.%3" )
			.arg( s.value( "DefaultDir", info.absolutePath() ).toString() )
			.arg( info.fileName() )
			.arg( s.value( "type" ,"ddoc" ).toString() );

		bool select = s.value( "AskSaveAs", false ).toBool();
		if( !select && QFile::exists( docname ) )
		{
			QMessageBox::StandardButton b = QMessageBox::warning( this, tr("DigiDoc3 client"),
				tr( "%1 already exists.<br />Do you want replace it?" ).arg( docname ),
				QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
			select = b == QMessageBox::No;
		}

		if( !Common::canWrite( docname ) )
		{
			select = true;
			QMessageBox::warning( this, tr("DigiDoc3 client"),
				tr( "You dont have suficient privilegs to write this fail into folder %1" ).arg( docname ) );
		}

		while( select )
		{
			docname = QFileDialog::getSaveFileName(
				this, tr("Save file"), docname, tr("Documents (*.bdoc *.ddoc)") );
			if( docname.isEmpty() )
				return false;
			QStringList exts = QStringList() << "bdoc" << "ddoc";
			if( !exts.contains( QFileInfo( docname ).suffix(), Qt::CaseInsensitive ) )
				docname.append( "." + s.value( "type" ,"ddoc" ).toString() );
			if( !Common::canWrite( docname ) )
			{
				QMessageBox::warning( this, tr("DigiDoc3 client"),
					tr( "You dont have suficient privilegs to write this fail into folder %1" ).arg( docname ) );
			}
			else
				select = false;
		}

		if( QFile::exists( docname ) )
			QFile::remove( docname );
		doc->create( docname );
	}

	if( !doc->signatures().isEmpty() )
	{
		QMessageBox::warning( this, tr("DigiDoc3 client"),
			tr( "You can not add files to signed document. "
				"Remove all signatures before adding files.") );
		return false;
	}

	// Check if file exist and ask confirmation to overwrite
	QList<digidoc::Document> docs = doc->documents();
	for( int i = 0; i < docs.size(); ++i )
	{
		if( QFileInfo( QString::fromUtf8( docs[i].getPath().data() ) ).fileName() ==
			QFileInfo( file ).fileName() )
		{
			QMessageBox::StandardButton btn = QMessageBox::warning( this,
				tr("File already in container"),
				tr("%1<br />already in container, ovewrite?")
					.arg( QFileInfo( file ).fileName() ),
				QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
			if( btn == QMessageBox::Yes )
			{
				doc->removeDocument( i );
				break;
			}
			else
				return true;
		}
	}

	doc->addFile( file );
	return true;
}

void MainWindow::buttonClicked( int button )
{
	switch( button )
	{
	case HeadSettings:
		showSettings();
		break;
	case HeadHelp:
		QDesktopServices::openUrl( QUrl( "http://support.sk.ee/" ) );
		break;
	case HomeView:
	{
		QString file = QFileDialog::getOpenFileName( this, tr("Open container"),
			QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ),
			tr("Documents (*.bdoc *.BDOC *.ddoc *.DDOC)") );
		if( !file.isEmpty() && doc->open( file ) )
			setCurrentPage( doc->signatures().isEmpty() ? Sign : View );
		break;
	}
	case HomeCrypt:
		if( !Common::startDetached( "qdigidoccrypto" ) )
			showWarning( tr("Failed to start process 'qdigidoccrypto'") );
		break;
	case HomeSign:
		if( stack->currentIndex() == Home &&
			Settings().value( "Client/Intro", true ).toBool() )
		{
			introCheck->setChecked( false );
			setCurrentPage( Intro );
			break;
		}
	case IntroNext:
	{
		if( !params.isEmpty() )
		{
			Q_FOREACH( const QString &param, params )
			{
				const QFileInfo f( param );
				if( !f.isFile() )
					continue;
				QStringList exts = QStringList() << "bdoc" << "ddoc";
				if( doc->isNull() && exts.contains( f.suffix(), Qt::CaseInsensitive ) )
				{
					if( doc->open( f.absoluteFilePath() ) )
						setCurrentPage( doc->signatures().isEmpty() ? Sign : View );
					params.clear();
					return;
				}
				else if( !addFile( f.absoluteFilePath() ) )
					break;
			}
			params.clear();
			if( !doc->isNull() )
				setCurrentPage( Sign );
		}
		else
		{
			QStringList list = QFileDialog::getOpenFileNames( this, tr("Select documents"),
				QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) );
			if( !list.isEmpty() )
			{
				Q_FOREACH( const QString &file, list )
				{
					if( !addFile( file ) )
						return;
				}
				setCurrentPage( Sign );
			}
			else if( doc->isNull() )
				setCurrentPage( Home );
		}

		Settings s;
		s.beginGroup( "Client" );
		signRoleInput->setText( s.value( "Role" ).toString() );
		signResolutionInput->setText( s.value( "Resolution" ).toString() );
		signCityInput->setText( s.value( "City" ).toString() );
		signStateInput->setText( s.value( "State" ).toString() );
		signCountryInput->setText( s.value( "Country" ).toString() );
		signZipInput->setText( s.value( "Zip" ).toString() );
		break;
	}
	case SignCancel:
		if( !doc->signatures().isEmpty() )
		{
			setCurrentPage( View );
			break;
		}
		if( !doc->documents().isEmpty() )
		{
			QMessageBox msgBox( QMessageBox::Question, tr("Save container"),
				tr("You added %n file(s) to container, but these are not signed yet.\n"
					"Should I keep unsigned documents or remove these?", "", doc->documents().size()) );
			msgBox.addButton( tr("Remove"), QMessageBox::ActionRole );
			QPushButton *keep = msgBox.addButton( tr("Keep"), QMessageBox::ActionRole );
			msgBox.exec();

			if( msgBox.clickedButton() == keep )
			{
				doc->save();
				setCurrentPage( View );
				break;
			}

			if( QFile::exists( doc->fileName() ) )
				QFile::remove( doc->fileName() );
		}
	case IntroBack:
	case ViewClose:
		doc->clear();
		if( quitOnClose )
			close();
		setCurrentPage( Home );
		break;
	case SignSign:
	{
		CheckConnection connection;
		if( !connection.check( "http://ocsp.sk.ee" ) )
		{
			showWarning( connection.error() );
			break;
		}
		AccessCert access( this );
		if( !access.validate() )
		{
			if( infoSignMobile->isChecked() || doc->activeCard().isEmpty() )
			{
				QDesktopServices::openUrl( QUrl( "http://www.sk.ee/toend/" ) );
				break;
			}
			if( !access.download( doc->signer(), doc->activeCard(),
					SslCertificate( doc->signCert() ).subjectInfo( "serialNumber" ) ) )
				break;
		}

		if( infoSignCard->isChecked() )
		{
			if( !doc->sign( signCityInput->text(), signStateInput->text(),
					signZipInput->text(), signCountryInput->text(),
					signRoleInput->text(), signResolutionInput->text() ) )
				break;
				doc->save();
		}
		else
		{
			MobileDialog *m = new MobileDialog( doc, this );
			m->setSignatureInfo( signCityInput->text(),
				signStateInput->text(), signZipInput->text(),
				signCountryInput->text(), signRoleInput->text(),
				signResolutionInput->text() );
			m->sign( infoMobileCode->text(), infoMobileCell->text() );
			m->exec();
			if ( !m->fName.isEmpty() && doc->signMobile( m->fName ) )
			{
				doc->save();
				doc->open( doc->fileName() );
			} else {
				m->deleteLater();
				break;
			}
			m->deleteLater();
		}
		SettingsDialog::saveSignatureInfo( signRoleInput->text(),
			signResolutionInput->text(), signCityInput->text(),
			signStateInput->text(), signCountryInput->text(),
			signZipInput->text() );
		setCurrentPage( View );
		break;
	}
	case ViewAddSignature:
		setCurrentPage( Sign );
		break;
	default: break;
	}
}

void MainWindow::changeCard( QAction *a )
{ QMetaObject::invokeMethod( doc, "selectCard", Q_ARG(QString,a->data().toString()) ); }
void MainWindow::changeLang( QAction *a ) { on_languages_activated( a->data().toUInt() ); }

void MainWindow::closeDoc()
{
	if( SettingsDialog *d = findChild<SettingsDialog*>() )
		d->reject();
	else
		buttonClicked( stack->currentIndex() == Sign ? SignCancel : ViewClose );
}

void MainWindow::dragEnterEvent( QDragEnterEvent *e )
{
	if( e->mimeData()->hasUrls() && stack->currentIndex() != View )
		e->acceptProposedAction();
}

void MainWindow::dropEvent( QDropEvent *e )
{
	Q_FOREACH( const QUrl &u, e->mimeData()->urls() )
	{
		if( u.scheme() == "file" )
			params << u.toLocalFile();
	}
	buttonClicked( HomeSign );
}

bool MainWindow::eventFilter( QObject *o, QEvent *e )
{
	if( e->type() == QEvent::FileOpen )
	{
		QFileOpenEvent *o = static_cast<QFileOpenEvent*>(e);
		QStringList exts = QStringList() << "p12" << "p12d";
		if( exts.contains( QFileInfo( o->file() ).suffix(), Qt::CaseInsensitive ) )
		{
			SettingsDialog s( this );
			s.addAction( closeAction );
			s.setP12Cert( o->file() );
			s.exec();
		}
		else
		{
			params << o->file();
			buttonClicked( HomeSign );
		}
		return true;
	}
	else
		return QWidget::eventFilter( o, e );
}

void MainWindow::enableSign()
{
	Settings s;
	s.beginGroup( "Client" );
	s.setValue( "MobileCode", infoMobileCode->text() );
	s.setValue( "MobileNumber", infoMobileCell->text() );
	s.endGroup();

	if( doc->isNull() || doc->documents().isEmpty() )
	{
		signButton->setEnabled( false );
		return;
	}

	bool mobile = infoSignMobile->isChecked();
	if( mobile )
	{
		signSigner->setText( QString( "%1 (%2)" )
			.arg( infoMobileCell->text() ).arg( infoMobileCode->text() ) );
	}

#ifndef Q_OS_WIN32
#warning revert before release
#endif
	if( (mobile && false /*&& !IKValidator::isValid( infoMobileCode->text() )*/) ||
		(!mobile && !doc->signCert().isValid()) )
	{
		signButton->setEnabled( false );
		if( mobile )
			signButton->setToolTip( tr("Personal code is not valid") );
		else if( !doc->signCert().isValid() )
			signButton->setToolTip( tr("Sign certificate is not valid") );
		else if( doc->signCert().isNull() )
			signButton->setToolTip( tr("No card in reader") );
		return;
	}

	bool cardOwnerSignature = false;
	const QByteArray serialNumber = mobile ?
		infoMobileCode->text().toLatin1() : doc->signCert().subjectInfo( "serialNumber" ).toLatin1();
	Q_FOREACH( const DigiDocSignature &c, doc->signatures() )
	{
		if( c.cert().subjectInfo( "serialNumber" ) == serialNumber )
		{
			cardOwnerSignature = true;
			break;
		}
	}
	signButton->setEnabled( !cardOwnerSignature );
	signButton->setToolTip( cardOwnerSignature ? tr("This container is signed by you") : QString() );
}

bool MainWindow::isLoaded() const { return m_loaded; }

void MainWindow::on_introCheck_stateChanged( int state )
{ Settings().setValue( "Client/Intro", state == Qt::Unchecked ); }

void MainWindow::on_languages_activated( int index )
{
	Settings().setValue( "Main/Language", lang[index] );

	switch( index )
	{
	case 1: QLocale::setDefault( QLocale( QLocale::English, QLocale::UnitedKingdom ) ); break;
	case 2: QLocale::setDefault( QLocale( QLocale::Russian, QLocale::RussianFederation ) ); break;
	default: QLocale::setDefault( QLocale( QLocale::Estonian, QLocale::Estonia ) ); break;
	}
	appTranslator->load( ":/translations/" + lang[index] );
	commonTranslator->load( ":/translations/common_" + lang[index] );
	qtTranslator->load( ":/translations/qt_" + lang[index] );
	retranslateUi( this );
	languages->setCurrentIndex( index );
	introNext->setText( tr( "Next" ) );
	signButton->setText( tr("Sign") );
	viewAddSignature->setText( tr("Add signature") );
	showCardStatus();
	setCurrentPage( (Pages)stack->currentIndex() );
}

void MainWindow::parseLink( const QString &link )
{
	if( link == "addFile" )
	{
		QStringList list = QFileDialog::getOpenFileNames( this, tr("Select documents"),
			QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) );
		if( !list.isEmpty() )
		{
			Q_FOREACH( const QString &file, list )
			{
				if( !addFile( file ) )
					return;
			}
			setCurrentPage( Sign );
		}
		else if( doc->isNull() )
			setCurrentPage( Home );
	}
	else if( link == "browse" )
	{
		QUrl url = QUrl::fromLocalFile( doc->fileName() );
		url.setScheme( "browse" );
		QDesktopServices::openUrl( url );
	}
	else if( link == "email" )
	{
		QUrl url;
		url.setScheme( "mailto" );
		url.addQueryItem( "subject", QFileInfo( doc->fileName() ).fileName() );
		url.addQueryItem( "attachment", QFileInfo( doc->fileName() ).absoluteFilePath() );
		QDesktopServices::openUrl( url );
	}
	else if( link == "print" )
	{
		QPrintPreviewDialog *dialog = new QPrintPreviewDialog( this );
		dialog->setWindowFlags( dialog->windowFlags() | Qt::WindowMinMaxButtonsHint );
		PrintSheet *p = new PrintSheet( doc, dialog );
		p->setVisible( false );
		connect( dialog, SIGNAL(paintRequested(QPrinter*)), p, SLOT(print(QPrinter*)) );
		dialog->exec();
	}
	else if( link == "saveAs" )
	{
		QString dir = QFileDialog::getExistingDirectory( this,
			tr("Select folder where files will be stored"),
			QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) );
		if( dir.isEmpty() )
			return;
		QAbstractItemModel *m = viewContentView->model();
		for( int i = 0; i < m->rowCount(); ++i )
		{
			QString source = m->index( i, 0 ).data( Qt::UserRole ).toString();
			QString dest = QString( "%1/%2" )
				.arg( dir ).arg( m->index( i, 0 ).data().toString() );
			if( source == dest )
				continue;
			if( QFile::exists( dest ) )
			{
				QMessageBox::StandardButton b = QMessageBox::warning( this, tr("DigiDoc3 client"),
					tr( "%1 already exists.<br />Do you want replace it?" ).arg( dest ),
					QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
				if( b == QMessageBox::No )
				{
					dest = QFileDialog::getSaveFileName( this, tr("Save file"), dest );
					if( dest.isEmpty() )
						continue;
				}
				else
					QFile::remove( dest );
			}
			QFile::copy( source, dest );
		}
	}
	else if( link == "openUtility" )
	{
		if( !Common::startDetached( "qesteidutil" ) )
			showWarning( tr("Failed to start process 'qesteidutil'") );
	}
}

void MainWindow::removeDocument( unsigned int index )
{
	doc->removeDocument( index );
	setCurrentPage( (Pages)stack->currentIndex() );
}

void MainWindow::setCurrentPage( Pages page )
{
	stack->setCurrentIndex( page );

	if( !doc->fileName().isEmpty() )
	{
		setWindowTitle( QString( "%1 - %2" )
			.arg( QFileInfo( doc->fileName() ).fileName() )
			.arg( tr("DigiDoc3 client") ) );
	}
	else
		setWindowTitle( tr("DigiDoc3 client") );

	switch( page )
	{
	case Sign:
	{
		signContentView->setContent( doc->documents() );
		signContentView->setColumnHidden( 3, !doc->signatures().isEmpty() );
		signAddFile->setVisible( doc->signatures().isEmpty() );
		enableSign();
		break;
	}
	case View:
	{
		viewContentView->setContent( doc->documents() );

		qDeleteAll( viewSignatures->findChildren<SignatureWidget*>() );

		int i = 0;
		bool cardOwnerSignature = false, invalid = false, test = false;
		QList<DigiDocSignature> signatures = doc->signatures();
		Q_FOREACH( const DigiDocSignature &c, signatures )
		{
			SignatureWidget *signature = new SignatureWidget( c, i, signatures.size() < 3, viewSignatures );
			viewSignaturesLayout->insertWidget( 0, signature );
			connect( signature, SIGNAL(removeSignature(unsigned int)),
				SLOT(viewSignaturesRemove(unsigned int)) );
			cardOwnerSignature = qMax( cardOwnerSignature,
				c.cert().subjectInfo( "serialNumber" ) == doc->signCert().subjectInfo( "serialNumber" ) );
			invalid = qMax( invalid, !signature->isValid() );
			test = qMax( test, signature->isTest() );
			++i;
		}

		viewFileName->setText( QString( "%1 <b>%2</b>" )
			.arg( tr("Container:") )
			.arg( QDir::toNativeSeparators( doc->fileName() ) ) );
		viewFileName->setToolTip( QDir::toNativeSeparators( doc->fileName() ) );

		if( !doc->signCert().isNull() )
		{
			if( !signatures.isEmpty() && cardOwnerSignature )
				viewFileStatus->setText( tr("This container is signed by you") );
			else if( !signatures.isEmpty() && !cardOwnerSignature )
				viewFileStatus->setText( tr("You have not signed this container") );
			else
				viewFileStatus->setText( tr("Container is unsigned") );
		}
		else
			viewFileStatus->clear();

		viewSignaturesLabel->setText( tr( "Signature(s)", "", signatures.size() ) );

		if( invalid )
			viewSignaturesError->setText( tr("NB! Invalid signature") );
		else if( test )
			viewSignaturesError->setText( tr("NB! Test signature") );
		else
			viewSignaturesError->clear();
		break;
	}
	default: break;
	}
}

void MainWindow::showCardStatus()
{
	signSigner->clear();

	if( infoSignMobile->isChecked() )
	{
		infoStack->setCurrentIndex( 1 );
		signSigner->setText( QString( "%1 (%2)" )
			.arg( infoMobileCell->text() ).arg( infoMobileCode->text() ) );
	}
	else
	{
		infoStack->setCurrentIndex( 0 );
		if( !doc->activeCard().isEmpty() && !doc->signCert().isNull() )
		{
			infoCard->setText( Common::tokenInfo( Common::SignCert, doc->activeCard(), doc->signCert() ) );
			SslCertificate c( doc->signCert() );
			signSigner->setText( c.toString( c.isTempel() ? "CN (serialNumber)" : "GN SN (serialNumber)" ) );
		}
		else if( !doc->activeCard().isEmpty() )
			infoCard->setText( tr("Loading data") );
		else if( doc->activeCard().isEmpty() )
			infoCard->setText( tr("No card in reader") );
	}

	cards->clear();
	cards->addItems( doc->presentCards() );
	cards->setVisible( doc->presentCards().size() > 1 );
	cards->setCurrentIndex( cards->findText( doc->activeCard() ) );
	qDeleteAll( cardsGroup->actions() );
	for( int i = 0; i < doc->presentCards().size(); ++i )
	{
		QAction *a = cardsGroup->addAction( new QAction( cardsGroup ) );
		a->setData( doc->presentCards().at( i ) );
		a->setShortcut( Qt::CTRL + (Qt::Key_1 + i) );
		addAction( a );
	}

	enableSign();
	setCurrentPage( (Pages)stack->currentIndex() );
}

void MainWindow::showSettings()
{
	SettingsDialog e( this );
	e.addAction( closeAction );
	e.exec();
}

void MainWindow::showWarning( const QString &msg )
{
	QMessageBox d( QMessageBox::Warning, tr("DigiDoc3 client"), msg, QMessageBox::Close | QMessageBox::Help, this );
	if( d.exec() == QMessageBox::Help )
		Common::showHelp( msg );
}

void MainWindow::viewSignaturesRemove( unsigned int num )
{
	doc->removeSignature( num );
	doc->save();
	setCurrentPage( doc->signatures().isEmpty() ? Sign : View );
}
