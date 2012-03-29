/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2012 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2012 Raul Metsma <raul@innovaatik.ee>
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

#include "AccessCert.h"
#include "Application.h"
#include "MobileDialog.h"
#include "PrintSheet.h"
#include "QSigner.h"
#include "SettingsDialog.h"
#include "SignatureDialog.h"

#include <common/CheckConnection.h>
#include <common/FileDialog.h>
#include <common/IKValidator.h>
#include <common/Settings.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <QDesktopServices>
#include <QDragEnterEvent>
#include <QMessageBox>
#include <QNetworkProxy>
#include <QPrinter>
#include <QPrintPreviewDialog>
#include <QTextStream>
#include <QUrl>

MainWindow::MainWindow( QWidget *parent )
:	QWidget( parent )
,	cardsGroup( new QActionGroup( this ) )
,	quitOnClose( false )
{
	setWindowFlags( Qt::Window|Qt::CustomizeWindowHint|Qt::WindowMinimizeButtonHint|Qt::WindowCloseButtonHint );
	setAttribute( Qt::WA_DeleteOnClose, true );
	setupUi( this );
	infoTypeGroup->setId( infoSignCard, 0 );
	infoTypeGroup->setId( infoSignMobile, 1 );

	cards->hide();
	cards->hack();
	languages->hack();

	Settings s;
	// Mobile
	infoMobileCode->setValidator( new IKValidator( infoMobileCode ) );
	infoMobileCode->setText( s.value( "Client/MobileCode" ).toString() );
	infoMobileCell->setText( s.value( "Client/MobileNumber", "+372" ).toString() );
	connect( infoMobileCode, SIGNAL(textEdited(QString)), SLOT(enableSign()) );
	connect( infoMobileCell, SIGNAL(textEdited(QString)), SLOT(enableSign()) );
	connect( infoTypeGroup, SIGNAL(buttonClicked(int)), SLOT(showCardStatus()) );

	// Buttons
	buttonGroup->setId( settings, HeadSettings );
	buttonGroup->setId( help, HeadHelp );
	buttonGroup->setId( about, HeadAbout );

	buttonGroup->setId( homeSign, HomeSign );
	buttonGroup->setId( homeView, HomeView );
	buttonGroup->setId( homeCrypt, HomeCrypt );

	buttonGroup->addButton(
		introButtons->addButton( tr( "I agree" ), QDialogButtonBox::AcceptRole ), IntroAgree );
	buttonGroup->addButton( introButtons->button( QDialogButtonBox::Cancel ), IntroBack );

	buttonGroup->addButton(
		signButtons->addButton( tr("Sign"), QDialogButtonBox::AcceptRole ), SignSign );
	buttonGroup->addButton( signButtons->button( QDialogButtonBox::Cancel ), SignCancel );

	buttonGroup->addButton(
		viewButtons->addButton( tr("Add signature"), QDialogButtonBox::AcceptRole ), ViewAddSignature );
	buttonGroup->addButton( viewButtons->button( QDialogButtonBox::Close ), ViewClose );

	connect( cards, SIGNAL(activated(QString)), qApp->signer(), SLOT(selectCard(QString)), Qt::QueuedConnection );
	connect( qApp->signer(), SIGNAL(dataChanged()), SLOT(showCardStatus()) );

	// Digidoc
	doc = new DigiDoc( this );

	// Translations
	lang << "et" << "en" << "ru";
	retranslate();
	QActionGroup *langGroup = new QActionGroup( this );
	for( int i = 0; i < lang.size(); ++i )
	{
		QAction *a = langGroup->addAction( new QAction( langGroup ) );
		a->setData( lang[i] );
		a->setShortcut( Qt::CTRL + Qt::SHIFT + Qt::Key_0 + i );
	}
	addActions( langGroup->actions() );
	connect( langGroup, SIGNAL(triggered(QAction*)), SLOT(changeLang(QAction*)) );
	connect( cardsGroup, SIGNAL(triggered(QAction*)), SLOT(changeCard(QAction*)) );

	// Views
	signContentView->setDocumentModel( doc->documentModel() );
	viewContentView->setDocumentModel( doc->documentModel() );
	signContentView->setColumnHidden( DocumentModel::Save, true );
	viewContentView->setColumnHidden( DocumentModel::Remove, true );
	connect( doc->documentModel(), SIGNAL(rowsInserted(QModelIndex,int,int)), SLOT(enableSign()) );
	connect( doc->documentModel(), SIGNAL(rowsRemoved(QModelIndex,int,int)), SLOT(enableSign()) );
	connect( doc->documentModel(), SIGNAL(modelReset()), SLOT(enableSign()) );

	if( QAbstractButton *b = infoTypeGroup->button( s.value( "Client/SignMethod", 0 ).toInt() ) )
		b->click();
}

bool MainWindow::addFile( const QString &file )
{
	QFileInfo fileinfo( file );
	if( doc->isNull() )
	{
		Settings s;
		s.beginGroup( "Client" );
		QString ext = s.value( "type" ,"ddoc" ).toString();
		QString docname = QString( "%1/%2.%3" )
			.arg( s.value( "DefaultDir", fileinfo.absolutePath() ).toString() )
			.arg( ext == fileinfo.suffix().toLower() ? fileinfo.fileName() : fileinfo.completeBaseName() )
			.arg( ext );

		bool select = s.value( "AskSaveAs", true ).toBool();
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
			qApp->showWarning(
				tr( "You don't have sufficient privileges to write this file into folder %1" ).arg( docname ) );
		}

		if( select )
		{
			docname = selectFile( docname );
			if( docname.isEmpty() )
				return false;
		}

		if( QFile::exists( docname ) )
			QFile::remove( docname );
		doc->create( docname );
	}

	if( !doc->signatures().isEmpty() )
	{
		qApp->showWarning( tr( "You can not add files to signed document. "
			"Remove all signatures before adding files.") );
		return false;
	}

	QString display = fileinfo.absoluteFilePath();
	if( display.size() > 80 )
		display = fontMetrics().elidedText( display, Qt::ElideLeft, 250 );

	if( !fileinfo.exists() )
	{
		qApp->showWarning( tr("File does not exists\n%1").arg( display ) );
		return false;
	}

	if( fileinfo.absoluteFilePath() == doc->fileName() )
	{
		qApp->showWarning( tr("Cannot add container to same container\n%1").arg( display ) );
		return false;
	}

	// Check if file exist and ask confirmation to overwrite
	for( int i = 0; i < signContentView->model()->rowCount(); ++i )
	{
		QModelIndex index = signContentView->model()->index( i, 0 );
		if( index.data().toString() == fileinfo.fileName() )
		{
			QMessageBox::StandardButton btn = QMessageBox::warning( this,
				tr("File already in container"),
				tr("%1\nalready in container, ovewrite?").arg( display ),
				QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
			if( btn == QMessageBox::Yes )
			{
				signContentView->model()->removeRow( index.row() );
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
	case HeadAbout:
		qApp->showAbout();
		break;
	case HeadSettings:
		qApp->showSettings();
		break;
	case HeadHelp:
		QDesktopServices::openUrl( QUrl( Common::helpUrl() ) );
		break;
	case HomeView:
	{
		QString file = FileDialog::getOpenFileName( this, tr("Open container"), QString(),
			tr("Documents (%1)").arg( "*.bdoc *.ddoc" ) );
		if( !file.isEmpty() && doc->open( file ) )
			setCurrentPage( doc->signatures().isEmpty() ? Sign : View );
		break;
	}
	case HomeCrypt:
		if( !Common::startDetached( "qdigidoccrypto" ) )
			qApp->showWarning( tr("Failed to start process '%1'").arg( "qdigidoccrypto" ) );
		break;
	case HomeSign:
		if( stack->currentIndex() == Home &&
			Settings().value( "Client/Intro", true ).toBool() )
		{
			introCheck->setChecked( false );
			setCurrentPage( Intro );
			break;
		}
	case IntroAgree:
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
					loadRoles();
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
			QStringList list = FileDialog::getOpenFileNames( this, tr("Select documents") );
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
		loadRoles();
		break;
	}
	case SignCancel:
		if( !doc->signatures().isEmpty() )
		{
			setCurrentPage( View );
			break;
		}
		if( signContentView->model()->rowCount() )
		{
			QMessageBox msgBox( QMessageBox::Question, tr("Save container"),
				tr("You added %n file(s) to container, but these are not signed yet.\n"
					"Should I keep unsigned documents or remove these?", "", signContentView->model()->rowCount()) );
			msgBox.addButton( tr("Remove"), QMessageBox::ActionRole );
			QPushButton *keep = msgBox.addButton( tr("Keep"), QMessageBox::ActionRole );
			msgBox.exec();

			if( msgBox.clickedButton() == keep )
			{
				save();
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
		buttonGroup->button( SignSign )->setEnabled( false );
		buttonGroup->button( SignSign )->setToolTip( tr("Signing in process") );
		CheckConnection connection;
		if( !qApp->confValue( Application::ProxyHost ).toString().isEmpty() )
		{
			connection.setProxy( QNetworkProxy(
				QNetworkProxy::HttpProxy,
				qApp->confValue( Application::ProxyHost ).toString(),
				qApp->confValue( Application::ProxyPort ).toUInt(),
				qApp->confValue( Application::ProxyUser ).toString(),
				qApp->confValue( Application::ProxyPass ).toString() ) );
		}

		if( !connection.check( "http://ocsp.sk.ee" ) )
		{
			qApp->showWarning( connection.errorString(), -1, connection.errorDetails(), "Check connection" );
			switch( connection.error() )
			{
			case QNetworkReply::ProxyConnectionRefusedError:
			case QNetworkReply::ProxyConnectionClosedError:
			case QNetworkReply::ProxyNotFoundError:
			case QNetworkReply::ProxyTimeoutError:
			case QNetworkReply::ProxyAuthenticationRequiredError:
			case QNetworkReply::UnknownProxyError:
				qApp->showSettings( 3 );
			default: break;
			}
			break;
		}

		AccessCert access( this );
		if( !access.validate() )
		{
			if( !access.download( infoSignMobile->isChecked() || qApp->signer()->token().card().isEmpty() ) )
				break;
			QMessageBox b( QMessageBox::Information, tr("DigiDoc3 client"),
				tr("Server access certificate has been installed") );
			b.setDefaultButton( b.addButton( tr("Continue signing"), QMessageBox::AcceptRole ) );
			b.addButton( QMessageBox::Cancel );
			if( b.exec() == QMessageBox::Cancel )
				break;
		}

		if( infoSignCard->isChecked() )
		{
			if( !doc->sign( signCityInput->text(), signStateInput->text(),
					signZipInput->text(), signCountryInput->text(),
					signRoleInput->text(), signResolutionInput->text() ) )
				break;
			save();
		}
		else
		{
			if( QFileInfo( doc->fileName() ).suffix().toLower() == "bdoc" )
			{
				qApp->showWarning( tr("BDOC signing is not supported, please upgrade software") );
				break;
			}

			QScopedPointer<MobileDialog> m( new MobileDialog( doc, this ) );
			m->setSignatureInfo( signCityInput->text(),
				signStateInput->text(), signZipInput->text(),
				signCountryInput->text(), signRoleInput->text(),
				signResolutionInput->text() );
			m->sign( infoMobileCode->text(), infoMobileCell->text() );
			m->exec();
			if( m->signature().isEmpty() || !doc->addSignature( m->signature() ) )
				break;
			save();
			doc->open( doc->fileName() );
		}
		SettingsDialog::saveSignatureInfo( signRoleInput->text(),
			signResolutionInput->text(), signCityInput->text(),
			signStateInput->text(), signCountryInput->text(),
			signZipInput->text() );
		Settings().setValue( "Client/SignMethod", infoStack->currentIndex() );
		setCurrentPage( View );
		break;
	}
	case ViewAddSignature:
		setCurrentPage( Sign );
		loadRoles();
		break;
	default: break;
	}
	enableSign();
}

void MainWindow::changeCard( QAction *a )
{ QMetaObject::invokeMethod( qApp->signer(), "selectCard", Qt::QueuedConnection, Q_ARG(QString,a->data().toString()) ); }
void MainWindow::changeLang( QAction *a ) { qApp->loadTranslation( a->data().toString() ); }

void MainWindow::closeDoc()
{ buttonClicked( stack->currentIndex() == Sign ? SignCancel : ViewClose ); }

void MainWindow::enableSign()
{
	Settings s;
	s.setValue( "Client/MobileCode", infoMobileCode->text() );
	s.setValue( "Client/MobileNumber", infoMobileCell->text() );
	QAbstractButton *button = buttonGroup->button( SignSign );
	button->setToolTip( QString() );
	TokenData t = qApp->signer()->token();

	if( doc->isNull() )
		button->setToolTip( tr("Container is not open") );
	else if( signContentView->model()->rowCount() == 0 )
		button->setToolTip( tr("Empty container") );
	else if( infoSignMobile->isChecked() )
	{
		signSigner->setText( QString( "%1 (%2)" )
			.arg( infoMobileCell->text() ).arg( infoMobileCode->text() ) );
		if( !IKValidator::isValid( infoMobileCode->text() ) )
			button->setToolTip( tr("Personal code is not valid") );
	}
	else
	{
		if( t.flags() & TokenData::PinLocked )
			button->setToolTip( tr("PIN is locked") );
		else if( t.cert().isNull() )
			button->setToolTip( tr("No card in reader") );
		else if( !t.cert().isValid() )
			button->setToolTip( tr("Sign certificate is not valid") );
		if( !t.cert().isNull() )
		{
			SslCertificate c( t.cert() );
			signSigner->setText( c.toString( c.showCN() ? "CN (serialNumber)" : "GN SN (serialNumber)" ) );
		}
		else
			signSigner->clear();
	}
	button->setEnabled( button->toolTip().isEmpty() );
	if( !button->isEnabled() )
		return;

	bool cardOwnerSignature = false;
	const QByteArray serialNumber = infoSignMobile->isChecked() ?
		infoMobileCode->text().toLatin1() : t.cert().subjectInfo( "serialNumber" ).toLatin1();
	Q_FOREACH( const DigiDocSignature &c, doc->signatures() )
	{
		if( c.cert().subjectInfo( "serialNumber" ) == serialNumber )
		{
			cardOwnerSignature = true;
			break;
		}
	}
	button->setEnabled( !cardOwnerSignature );
	button->setToolTip( cardOwnerSignature ? tr("This container is signed by you") : QString() );
}

bool MainWindow::event( QEvent *e )
{
	switch( e->type() )
	{
	case QEvent::DragEnter:
	{
		QDragEnterEvent *d = static_cast<QDragEnterEvent*>( e );
		if( d->mimeData()->hasUrls() && stack->currentIndex() != View )
			d->acceptProposedAction();
		return QWidget::event( e );
	}
	case QEvent::Drop:
	{
		QDropEvent *d = static_cast<QDropEvent*>( e );
		Q_FOREACH( const QUrl &u, d->mimeData()->urls() )
		{
			if( u.scheme() == "file" )
				params << u.toLocalFile();
		}
		buttonClicked( HomeSign );
		return QWidget::event( e );
	}
	case QEvent::Close:
		closeDoc();
		return QWidget::event( e );
	case QEvent::LanguageChange:
		retranslate();
		return QWidget::event( e );
	default:
		return QWidget::event( e );
	}
}

void MainWindow::loadRoles()
{
	Settings s;
	s.beginGroup( "Client" );
	signRoleInput->setText( s.value( "Role" ).toString() );
	signResolutionInput->setText( s.value( "Resolution" ).toString() );
	signCityInput->setText( s.value( "City" ).toString() );
	signStateInput->setText( s.value( "State" ).toString() );
	signCountryInput->setText( s.value( "Country" ).toString() );
	signZipInput->setText( s.value( "Zip" ).toString() );
}

void MainWindow::on_introCheck_stateChanged( int state )
{ Settings().setValue( "Client/Intro", state == Qt::Unchecked ); }

void MainWindow::on_languages_activated( int index )
{ qApp->loadTranslation( lang[index] ); }

void MainWindow::open( const QStringList &_params )
{
	quitOnClose = true;
	params = _params;
	buttonClicked( HomeSign );
}

void MainWindow::parseLink( const QString &link )
{
	if( link == "addFile" )
	{
		QStringList list = FileDialog::getOpenFileNames( this, tr("Select documents") );
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
	else if( link == "encrypt" )
	{
		Common::startDetached( "qdigidoccrypto", QStringList() << doc->fileName() );
	}
	else if( link == "print" )
	{
		QPrinter printer;
		printer.setPaperSize( QPrinter::A4 );
		printer.setOrientation( QPrinter::Portrait );
		QPrintPreviewDialog *dialog = new QPrintPreviewDialog( &printer, this );
		dialog->setWindowFlags( dialog->windowFlags() | Qt::WindowMinMaxButtonsHint );
		connect( dialog, SIGNAL(paintRequested(QPrinter*)), SLOT(printSheet(QPrinter*)) );
		dialog->setMinimumHeight( 700 );
		dialog->exec();
	}
	else if( link == "save" )
	{
		QString file = selectFile( doc->fileName() );
		if( !file.isEmpty() )
			doc->save( file );
		setCurrentPage( View );
	}
	else if( link == "saveAs" )
	{
		QString dir = FileDialog::getExistingDirectory( this,
			tr("Select folder where files will be stored") );
		if( dir.isEmpty() )
			return;
		DocumentModel *m = doc->documentModel();
		for( int i = 0; i < m->rowCount(); ++i )
		{
			QModelIndex index = m->index( i, 0 );
			QString source = index.data( Qt::UserRole ).toString();
			QString dest = m->mkpath( index, dir );
			if( source == dest )
				continue;
			if( QFile::exists( dest ) )
			{
				QMessageBox::StandardButton b = QMessageBox::warning( this, tr("DigiDoc3 client"),
					tr( "%1 already exists.<br />Do you want replace it?" ).arg( dest ),
					QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
				if( b == QMessageBox::No )
				{
					dest = FileDialog::getSaveFileName( this, tr("Save file"), dest );
					if( dest.isEmpty() )
						continue;
				}
				else
					QFile::remove( dest );
			}
			m->copy( index, dir );
		}
	}
	else if( link == "openUtility" )
	{
		if( !Common::startDetached( "qesteidutil" ) )
			qApp->showWarning( tr("Failed to start process '%1'").arg( "qesteidutil" ) );
	}
}

void MainWindow::printSheet( QPrinter *printer )
{
	PrintSheet p( doc, printer );
}

void MainWindow::retranslate()
{
	retranslateUi( this );
	languages->setCurrentIndex( lang.indexOf( Settings::language() ) );
	buttonGroup->button( IntroAgree )->setText( tr("I agree") );
	buttonGroup->button( SignSign )->setText( tr("Sign") );
	buttonGroup->button( ViewAddSignature )->setText( tr("Add signature") );
	showCardStatus();
	setCurrentPage( (Pages)stack->currentIndex() );
}

void MainWindow::save()
{
	if( !Common::canWrite( doc->fileName() ) &&
		QMessageBox::Yes == QMessageBox::warning( this, tr("DigiDoc3 client"),
			tr("Cannot alter container %1. Save different location?")
				.arg( doc->fileName().normalized( QString::NormalizationForm_C ) ),
			QMessageBox::Yes|QMessageBox::No, QMessageBox::Yes ) )
	{
		QString file = selectFile( doc->fileName() );
		if( !file.isEmpty() )
		{
			doc->save( file );
			return;
		}
	}
	doc->save();
}

QString MainWindow::selectFile( const QString &filename )
{
	QString file = filename;
	Q_FOREVER
	{
		QStringList exts = QStringList() << Settings().value( "Client/type", "ddoc" ).toString();
		exts << (exts[0] == "ddoc" ? "bdoc" : "ddoc");
		file = FileDialog::getSaveFileName( this, tr("Save file"), file,
			tr("Documents (%1)").arg( QString( "*.%1 *.%2" ).arg( exts[0], exts[1] ) ) );
		if( file.isEmpty() )
			return QString();
		if( !exts.contains( QFileInfo( file ).suffix(), Qt::CaseInsensitive ) )
			file.append( "." + exts[0] );
		if( !Common::canWrite( file ) )
			qApp->showWarning(
				tr( "You don't have sufficient privileges to write this file into folder %1" ).arg( file ) );
		else
			return file;
	}
}

void MainWindow::setCurrentPage( Pages page )
{
	stack->setCurrentIndex( page );

	if( !doc->fileName().isEmpty() )
	{
		setWindowTitle( QString( "%1 - %2" )
			.arg( QFileInfo( doc->fileName().normalized( QString::NormalizationForm_C ) ).fileName() )
			.arg( tr("DigiDoc3 client") ) );
	}
	else
		setWindowTitle( tr("DigiDoc3 client") );

	switch( page )
	{
	case Sign:
	{
		signContentView->setColumnHidden( DocumentModel::Remove, !doc->signatures().isEmpty() );
		signAddFile->setVisible( doc->signatures().isEmpty() );
		break;
	}
	case View:
	{
		qDeleteAll( viewSignatures->findChildren<SignatureWidget*>() );

		int i = 0;
		bool cardOwnerSignature = false, invalid = false, test = false, weak = false;
		QList<DigiDocSignature> signatures = doc->signatures();
		Q_FOREACH( const DigiDocSignature &c, signatures )
		{
			SignatureWidget *signature = new SignatureWidget( c, i, viewSignatures );
			viewSignaturesLayout->insertWidget( 0, signature );
			connect( signature, SIGNAL(removeSignature(unsigned int)),
				SLOT(viewSignaturesRemove(unsigned int)) );
			cardOwnerSignature = qMax( cardOwnerSignature,
				c.cert().subjectInfo( "serialNumber" ) == qApp->signer()->token().cert().subjectInfo( "serialNumber" ) );
			invalid = qMax( invalid, c.validate() != DigiDocSignature::Valid );
			test = qMax( test, c.isTest() );
			weak = qMax( weak, c.weakDigestMethod() );
			++i;
		}

		viewFileName->setToolTip( QDir::toNativeSeparators( doc->fileName().normalized( QString::NormalizationForm_C ) ) );
		viewFileName->setText( viewFileName->fontMetrics().elidedText(
			viewFileName->toolTip(), Qt::ElideMiddle, viewFileName->width() ) );

		if( !qApp->signer()->token().cert().isNull() )
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
		else if( weak )
			viewSignaturesError->setText( tr("NB! Weak signature") );
		else
			viewSignaturesError->clear();
		break;
	}
	default: break;
	}
}

void MainWindow::showCardStatus()
{
	Application::restoreOverrideCursor();
	TokenData t = qApp->signer()->token();
	if( !t.card().isEmpty() && !t.cert().isNull() )
	{
		infoCard->setText( t.toHtml() );
		infoCard->setAccessibleDescription( t.toAccessible() );
	}
	else if( !t.card().isEmpty() )
	{
		infoCard->setText( tr("Loading data") );
		infoCard->setAccessibleDescription( tr("Loading data") );
		Application::setOverrideCursor( Qt::BusyCursor );
	}
	else if( t.card().isEmpty() )
	{
		infoCard->setText( tr("No card in reader") );
		infoCard->setAccessibleDescription( tr("No card in reader") );
	}

	cards->clear();
	cards->addItems( t.cards() );
	cards->setVisible( t.cards().size() > 1 );
	cards->setCurrentIndex( cards->findText( t.card() ) );
	qDeleteAll( cardsGroup->actions() );
	for( int i = 0; i < t.cards().size(); ++i )
	{
		QAction *a = cardsGroup->addAction( new QAction( cardsGroup ) );
		a->setData( t.cards().at( i ) );
		a->setShortcut( Qt::CTRL + (Qt::Key_1 + i) );
	}
	addActions( cardsGroup->actions() );

	enableSign();
}

void MainWindow::viewSignaturesRemove( unsigned int num )
{
	doc->removeSignature( num );
	save();
	enableSign();
	setCurrentPage( doc->signatures().isEmpty() ? Sign : View );
}
