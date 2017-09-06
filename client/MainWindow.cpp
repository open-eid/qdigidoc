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

#include "MainWindow.h"

#include "AccessCert.h"
#include "Application.h"
#include "CheckConnection.h"
#include "FileDialog.h"
#include "MobileDialog.h"
#include "PrintSheet.h"
#include "QSigner.h"
#include "SettingsDialog.h"
#include "SignatureDialog.h"

#include <common/IKValidator.h>
#include <common/Settings.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <QtCore/QMimeData>
#include <QtCore/QProcess>
#include <QtCore/QUrl>
#include <QtCore/QUrlQuery>
#include <QtGui/QDesktopServices>
#include <QtGui/QDragEnterEvent>
#include <QtNetwork/QNetworkProxy>
#include <QtPrintSupport/QPrinter>
#include <QtPrintSupport/QPrinterInfo>
#include <QtPrintSupport/QPrintPreviewDialog>
#include <QtWidgets/QCompleter>
#include <QtWidgets/QMessageBox>

const int MainWindow::SIGNATURE_COL_HDR_WIDTH = 274;

MainWindow::MainWindow( QWidget *parent )
	: QWidget( parent )
	, cardsGroup( new QActionGroup( this ) )
	, quitOnClose( false )
	, prevpage( Home )
	, message( 0 )
	, warnOnUnsignedDocCancel( true )
{
	setAttribute( Qt::WA_DeleteOnClose, true );
	setupUi( this );
	setFixedSize( geometry().size() );
	message = new QLabel( stack->widget( Sign ) );
	message->setObjectName( "warning" );
	message->setAlignment( Qt::AlignCenter );
	message->setWordWrap( true );
	message->setFixedSize( 400, 200 );
	connect( message, SIGNAL(linkActivated(QString)), this, SLOT(messageClicked(QString)) );
	message->hide();

#if defined(Q_OS_WIN) || defined(Q_OS_MAC)
	QString background = qApp->applicationDirPath() + "/qdigidocclient.png";
#else
	QString background = DATADIR "/qdigidoc/qdigidocclient.png";
#endif
	if(QFile::exists(background))
	{
		label->setPixmap(QPixmap());
		setStyleSheet(QString("#background { background-image: url(\"%1\"); }").arg(background));
		style()->unpolish(this);
		style()->polish(this);
	}

	infoTypeGroup->setId( infoSignCard, 0 );
	infoTypeGroup->setId( infoSignMobile, 1 );

	cards->hide();

	Settings s;
	Settings s2(qApp->applicationName());
	// Mobile
	infoMobileCode->setValidator( new IKValidator( infoMobileCode ) );
	infoMobileCode->setText( s.value( "Client/MobileCode" ).toString() );
	infoMobileCell->setValidator( new NumberValidator( infoMobileCell ) );
	infoMobileCell->setText( s.value( "Client/MobileNumber" ).toString() );
	infoMobileSettings->setChecked( s2.value( "MobileSettings", true ).toBool() );
	connect( infoMobileCode, SIGNAL(textEdited(QString)), SLOT(enableSign()) );
	connect( infoMobileCell, SIGNAL(textEdited(QString)), SLOT(enableSign()) );
	connect( infoTypeGroup, SIGNAL(buttonClicked(int)), SLOT(showCardStatus()) );
	connect( infoMobileSettings, &QCheckBox::clicked, [=](bool checked) {
		Settings s;
		s.setValueEx("Client/MobileCode", checked ? infoMobileCode->text() : QString(), QString());
		s.setValueEx("Client/MobileNumber", checked ? infoMobileCell->text() : QString(), QString());
		Settings(qApp->applicationName()).setValueEx("MobileSettings", checked, true);
	});
	if(s2.value("type").toString() == "ddoc")
		s2.remove("type");

	// Buttons
	buttonGroup->setId( settings, HeadSettings );
	buttonGroup->setId( help, HeadHelp );
	buttonGroup->setId( about, HeadAbout );

	buttonGroup->setId( homeSign, HomeSign );
	buttonGroup->setId( homeView, HomeView );
	buttonGroup->setId( homeCrypt, HomeCrypt );

	buttonGroup->setId( signAddFile, SignAdd );

	buttonGroup->setId( viewEmail, ViewEmail );
	buttonGroup->setId( viewBrowse, ViewBrowse );
	buttonGroup->setId( viewPrint, ViewPrint );
	buttonGroup->setId( viewEncrypt, ViewEncrypt );
	buttonGroup->setId( viewFileNameSave, ViewSaveAs );
	buttonGroup->setId( viewSaveAs, ViewSaveFiles );

	buttonGroup->addButton(
		introButtons->addButton( tr( "I agree" ), QDialogButtonBox::AcceptRole ), IntroAgree );
	buttonGroup->addButton( introButtons->button( QDialogButtonBox::Cancel ), IntroBack );

	buttonGroup->addButton(
		signButtons->addButton( tr("Sign"), QDialogButtonBox::AcceptRole ), SignSign );
	buttonGroup->addButton( signButtons->button( QDialogButtonBox::Cancel ), SignCancel );

	buttonGroup->addButton(
		viewButtons->addButton( tr("Add signature"), QDialogButtonBox::AcceptRole ), ViewAddSignature );
	buttonGroup->addButton( viewButtons->button( QDialogButtonBox::Close ), ViewClose );

	connect( cards, SIGNAL(activated(QString)), qApp->signer(), SLOT(selectSignCard(QString)), Qt::QueuedConnection );
	connect( qApp->signer(), SIGNAL(signDataChanged(TokenData)), SLOT(showCardStatus()) );
	connect( viewFileName, SIGNAL(linkActivated(QString)), this, SLOT(messageClicked(QString)) );

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
	signContentView->setDocumentModel(doc->documentModel());
	signContentView->setDigiDoc(doc);
	viewContentView->setDocumentModel(doc->documentModel());
	signContentView->setColumnHidden( DocumentModel::Save, true );
	signContentView->setColumnHidden( DocumentModel::Id, true );
	viewContentView->setColumnHidden( DocumentModel::Remove, true );
	viewContentView->setColumnHidden( DocumentModel::Id, true );

	connect( doc->documentModel(), SIGNAL(rowsInserted(QModelIndex,int,int)), SLOT(enableSign()) );
	connect( doc->documentModel(), SIGNAL(rowsRemoved(QModelIndex,int,int)), SLOT(enableSign()) );
	connect( doc->documentModel(), SIGNAL(modelReset()), SLOT(enableSign()) );

	if( QAbstractButton *b = infoTypeGroup->button( s.value( "Client/SignMethod", 0 ).toInt() ) )
		b->click();

	for(QLineEdit *line: {signRoleInput, signResolutionInput, signCityInput, signStateInput, signCountryInput, signZipInput})
	{
		QCompleter *completer = new QCompleter(s.value(line->objectName()).toStringList(), line);
		completer->setMaxVisibleItems(10);
		completer->setCompletionMode(QCompleter::PopupCompletion);
		completer->setCaseSensitivity(Qt::CaseInsensitive);
		line->setCompleter(completer);
		connect(line, &QLineEdit::editingFinished, [=] {
			if(line->text().isEmpty())
				return;
			Settings s;
			QStringList list = s.value(line->objectName()).toStringList();
			if(list.contains(line->text(), Qt::CaseInsensitive))
				return;
			list.insert(0, line->text());
			if(list.size() > 10)
				list.removeLast();
			s.setValueEx(line->objectName(), list, QStringList());
		});
	}
}

bool MainWindow::addFile( const QString &file )
{
	QFileInfo fileinfo( file );
	if( doc->isNull() )
	{
		Settings s;
		s.beginGroup( "Client" );

		QString ext = Settings(qApp->applicationName()).value( "type" ,"bdoc" ).toString();
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

#ifndef Q_OS_MAC
		if( !FileDialog::fileIsWritable( docname ) )
		{
			select = true;
			qApp->showWarning(
				tr( "You don't have sufficient privileges to write this file into folder %1" ).arg( docname ) );
		}
#endif

		if( select )
		{
			docname = selectFile( docname, false );
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
			tr("Documents (%1%2)").arg( "*.bdoc *.ddoc *.asice *.sce *.asics *.scs *.edoc *.adoc")
				.arg(qApp->confValue(Application::SiVaUrl).toString().isEmpty() ? "" : " *.pdf") );
		if( !file.isEmpty() && doc->open( file ) )
		{
			warnOnUnsignedDocCancel = false;
			setCurrentPage( doc->signatures().isEmpty() ? Sign : View );
		}
		break;
	}
	case HomeCrypt:
		qApp->showCrypto();
		break;
	case IntroAgree:
		setCurrentPage( Sign );
		break;
	case HomeSign:
	{
		if( !params.isEmpty() )
		{
			for(const QString &param: params)
			{
				const QFileInfo f( param );
				if( !f.isFile() )
					continue;
				QStringList exts = QStringList() << "bdoc" << "ddoc" << "asice" << "sce" << "asics" << "scs" << "edoc" << "adoc";
				if( doc->isNull() && exts.contains( f.suffix(), Qt::CaseInsensitive ) )
				{
					if( doc->open( f.absoluteFilePath() ) )
					{
						warnOnUnsignedDocCancel = false;
						setCurrentPage( doc->signatures().isEmpty() ? Sign : View );
						enableSign();
					}
					params.clear();
					loadRoles();
					return;
				}
				else if( !addFile( f.absoluteFilePath() ) )
					break;
			}
			warnOnUnsignedDocCancel = true;
			params.clear();
			if( !doc->isNull() )
				setCurrentPage( Sign );
		}
		else
		{
			warnOnUnsignedDocCancel = true;

			const QStringList list = FileDialog::getOpenFileNames(this, tr("Select documents"));
			for(const QString &file: list)
			{
				if( !addFile( file ) )
					return;
			}
			setCurrentPage( doc->isNull() ? Home : Sign );
		}
		loadRoles();
		break;
	}
	case SignAdd:
	{
		const QStringList list = FileDialog::getOpenFileNames(this, tr("Select documents"));
		if( !list.isEmpty() )
		{
			for(const QString &file: list)
			{
				if( !addFile( file ) )
					return;
			}
			setCurrentPage( Sign );
		}
		else if( doc->isNull() )
			setCurrentPage( Home );
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
			if ( warnOnUnsignedDocCancel )
			{
				QMessageBox msgBox( QMessageBox::Question, tr("Save container"),
					tr("You've added %n file(s) to container, but these are not signed yet.\n"
						"Should I keep the unsigned container or remove it?", "", signContentView->model()->rowCount()) );
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
			else
			{
				save();
				setCurrentPage( View );
				break;
			}
		}
	case IntroBack:
		if( prevpage == View )
		{
			setCurrentPage( View );
			break;
		}
	case ViewClose:
		doc->clear();
		warnOnUnsignedDocCancel = true;
		if( quitOnClose )
			close();
		setCurrentPage( Home );
		break;
	case ViewBrowse:
	{
		QUrl url = QUrl::fromLocalFile( doc->fileName() );
		url.setScheme( "browse" );
		QDesktopServices::openUrl( url );
		break;
	}
	case ViewEmail:
	{
		QUrlQuery q;
		q.addQueryItem("subject", QFileInfo( doc->fileName() ).fileName());
		q.addQueryItem("attachment", QFileInfo( doc->fileName() ).absoluteFilePath());
		QUrl url;
		url.setScheme("mailto");
		url.setQuery(q);
		QDesktopServices::openUrl(url);
		break;
	}
	case ViewEncrypt:
	{
		qApp->showCrypto( QStringList() << doc->fileName() );
		break;
	}
	case ViewPrint:
	{
#ifdef Q_OS_WIN
		if( QPrinterInfo::availablePrinters().isEmpty() )
		{
			qApp->showWarning(
				tr("In order to view Validity Confirmation Sheet there has to be at least one printer installed!") );
			break;
		}
#endif
		QPrintPreviewDialog *dialog = new QPrintPreviewDialog( this );
		dialog->printer()->setPaperSize( QPrinter::A4 );
		dialog->printer()->setOrientation( QPrinter::Portrait );
		dialog->setMinimumHeight( 700 );
		connect( dialog, &QPrintPreviewDialog::paintRequested, [=](QPrinter *printer){
			PrintSheet(doc, printer);
		});
		dialog->exec();
		dialog->deleteLater();
		break;
	}
	case ViewSaveAs:
	{
		QString file = selectFile( doc->fileName(), true );
		if( !file.isEmpty() )
			doc->save( file );
		setCurrentPage( View );
		break;
	}
	case ViewSaveFiles:
	{
		QString dir = FileDialog::getExistingDirectory( this,
			tr("Select folder where files will be stored") );
		if( dir.isEmpty() )
			return;
		QMessageBox::StandardButton b = QMessageBox::No;	// default
		DocumentModel *m = doc->documentModel();
		for( int i = 0; i < m->rowCount(); ++i )
		{
			QModelIndex index = m->index( i, DocumentModel::Name );
			QString dest = dir + QDir::separator() + index.data( Qt::UserRole ).toString();
			if( QFile::exists( dest ) )
			{
				if( b == QMessageBox::YesToAll )
				{
					QFile::remove( dest );
					m->save( index, dest );
					continue;
				}
				b = QMessageBox::warning( this, tr("DigiDoc3 client"),
					tr("%1 already exists.<br />Do you want replace it?").arg( dest ),
					QMessageBox::Yes | QMessageBox::No | QMessageBox::YesToAll | QMessageBox::Cancel, QMessageBox::No );

				if( b == QMessageBox::Cancel )
				{
					break;
				}
				else if( b == QMessageBox::No )
				{
					dest = FileDialog::getSaveFileName( this, tr("Save file"), dest );
					if( dest.isEmpty() )
						continue;
				}
				else
					QFile::remove( dest );
			}
			m->save( index, dest );
		}
		break;
	}
	case SignSign:
	{
		if( buttonGroup->button( SignSign )->property("selfsigned").toBool() )
		{
			QMessageBox b( QMessageBox::Information, tr("DigiDoc3 client"),
				tr("The document has already been signed by you."), QMessageBox::Cancel, this );
			b.setDefaultButton( b.addButton( tr("Continue signing"), QMessageBox::AcceptRole ) );
			if( b.exec() == QMessageBox::Cancel )
				break;
		}
		buttonGroup->button( SignSign )->setEnabled( false );
		buttonGroup->button( SignSign )->setToolTip( tr("Signing in process") );
		CheckConnection connection;
		if( !connection.check( "http://ocsp.sk.ee" ) )
		{
			qApp->showWarning(connection.errorString(), connection.errorDetails());
			switch( connection.error() )
			{
			case QNetworkReply::ProxyConnectionRefusedError:
			case QNetworkReply::ProxyConnectionClosedError:
			case QNetworkReply::ProxyNotFoundError:
			case QNetworkReply::ProxyTimeoutError:
			case QNetworkReply::ProxyAuthenticationRequiredError:
			case QNetworkReply::UnknownProxyError:
				qApp->showSettings( SettingsDialog::NetworkSettings );
			default: break;
			}
			break;
		}

		AccessCert access( this );
		if( !access.validate() )
			break;

		if( infoSignCard->isChecked() )
		{
			if( !doc->sign( signCityInput->text(), signStateInput->text(),
					signZipInput->text(), signCountryInput->text(),
					signRoleInput->text(), signResolutionInput->text() ) )
				break;
			access.increment();
			save();
		}
		else
		{
			MobileDialog m(this);
			m.setSignatureInfo( signCityInput->text(),	signStateInput->text(),
				signZipInput->text(), signCountryInput->text(),
				QStringList() << signRoleInput->text() << signResolutionInput->text() );
			m.sign( doc, infoMobileCode->text(), infoMobileCell->text() );
			if( !m.exec() || !doc->addSignature( m.signature() ) )
				break;
			access.increment();
			save();
		}
		SettingsDialog::saveSignatureInfo( signRoleInput->text(),
			signResolutionInput->text(), signCityInput->text(),
			signStateInput->text(), signCountryInput->text(),
			signZipInput->text() );
		Settings().setValueEx( "Client/SignMethod", infoStack->currentIndex(), 0 );
		setCurrentPage( View );
		QApplication::alert(this, 0);
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
{ QMetaObject::invokeMethod( qApp->signer(), "selectSignCard", Qt::QueuedConnection, Q_ARG(QString,a->data().toString()) ); }
void MainWindow::changeLang( QAction *a ) { qApp->loadTranslation( a->data().toString() ); }

void MainWindow::closeDoc()
{ buttonClicked( stack->currentIndex() == Sign ? SignCancel : ViewClose ); }

void MainWindow::enableSign()
{
	if( infoMobileSettings->isChecked() )
	{
		Settings s;
		s.setValueEx( "Client/MobileCode", infoMobileCode->text(), QString() );
		s.setValueEx( "Client/MobileNumber", infoMobileCell->text(), QString() );
	}
	QAbstractButton *button = buttonGroup->button( SignSign );
	button->setToolTip( QString() );
	TokenData t = qApp->signer()->tokensign();
	showWarning( QString() );

	int warning = 0;
	for(const DigiDocSignature &s: doc->signatures())
	{
		s.validate();
		if( s.warning() )
			warning |= s.warning();
	}

	if( doc->isNull() )
		button->setToolTip( tr("Container is not open") );
	else if( doc->isService() )
		button->setToolTip( tr("Signing not allowed.") );
	else if( doc->isReadOnlyTS() )
	{
		showWarning( SignatureDialog::tr(
			"The current file is a timestamped ASiC-S container. "
			"You are not allowed to add or remove timestamps (signatures) to this container.") );
		button->setToolTip( tr("Signing not allowed.") );
	}
	else if( !doc->isSupported() )
	{
		showWarning( SignatureDialog::tr(
			"The current file is a DigiDoc container that is not supported officially any longer. "
			"You are not allowed to add or remove signatures to this container. "
			"<a href='http://www.id.ee/?id=36161'>Additional info</a>.") );
		button->setToolTip( tr("Signing not allowed.") );
	}
	else if( warning & DigiDocSignature::DigestWeak )
	{
		showWarning( SignatureDialog::tr(
			"The current BDOC container uses weaker encryption method than officialy accepted in Estonia.") );
		button->setToolTip( tr("Signing not allowed.") );
	}
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
		else if( !SslCertificate(t.cert()).isValid() )
			button->setToolTip( tr("Sign certificate is not valid") );
		if( !t.cert().isNull() )
		{
			SslCertificate c( t.cert() );
			signSigner->setText( signSigner->fontMetrics().elidedText(
				c.toString( c.showCN() ? "CN (serialNumber)" : "GN SN (serialNumber)" ), Qt::ElideMiddle, SIGNATURE_COL_HDR_WIDTH ) );
		}
		else
			signSigner->clear();
	}

	if( doc->signatures().isEmpty() )
		viewFileStatus->setText( tr("Container is unsigned") );
	else
		viewFileStatus->clear();
	button->setEnabled( button->toolTip().isEmpty() );
	if( !button->isEnabled() )
		return;

	const QString serialNumber = infoSignMobile->isChecked() ?
		infoMobileCode->text() : SslCertificate(t.cert()).subjectInfo( "serialNumber" );
	QList<DigiDocSignature> list = doc->signatures();
	bool cardOwnerSignature = !serialNumber.isEmpty() && list.cend() !=
		std::find_if(list.cbegin(), list.cend(), [&](const DigiDocSignature &c){
			return SslCertificate(c.cert()).subjectInfo("serialNumber") == serialNumber;
	});
	button->setProperty( "selfsigned", cardOwnerSignature );
	button->setToolTip( cardOwnerSignature ? tr("This container is signed by you") : QString() );
	if( viewFileStatus->text().isEmpty() )
		viewFileStatus->setText( cardOwnerSignature ? tr("This container is signed by you") : tr("You have not signed this container") );
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
		for(const QUrl &u: d->mimeData()->urls())
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

void MainWindow::messageClicked( const QString &link )
{
	if( link == "close" )
		showWarning( QString() );
	else if( link == viewFileName->toolTip() )
		buttonClicked( ViewBrowse );
	else
		QDesktopServices::openUrl( link );
}

void MainWindow::on_introCheck_stateChanged( int state )
{ Settings(qApp->applicationName()).setValueEx( "ClientIntro", state == Qt::Unchecked, true ); }

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
	if( link == "openUtility" )
	{
#ifdef Q_OS_MAC
		if( !QProcess::startDetached( "/usr/bin/open", QStringList() << "-a" << "qesteidutil" ) )
#else
		if( !QProcess::startDetached( "qesteidutil" ) )
#endif
			qApp->showWarning( tr("Failed to start process '%1'").arg( "qesteidutil" ) );
	}
}

void MainWindow::retranslate()
{
	retranslateUi( this );
	languages->setCurrentIndex( lang.indexOf( Settings::language() ) );
	buttonGroup->button( IntroAgree )->setText( tr("I agree") );
	buttonGroup->button( SignSign )->setText( tr("Sign") );
	buttonGroup->button( ViewAddSignature )->setText( tr("Add signature") );
	version->setText( windowTitle() + " " + qApp->applicationVersion() );
	showCardStatus();
	setCurrentPage( (Pages)stack->currentIndex() );
}

void MainWindow::save()
{
	if( !FileDialog::fileIsWritable( doc->fileName() ) &&
		QMessageBox::Yes == QMessageBox::warning( this, tr("DigiDoc3 client"),
			tr("Cannot alter container %1. Save different location?")
				.arg( doc->fileName().normalized( QString::NormalizationForm_C ) ),
			QMessageBox::Yes|QMessageBox::No, QMessageBox::Yes ) )
	{
		QString file = selectFile( doc->fileName(), true );
		if( !file.isEmpty() )
		{
			doc->save( file );
			return;
		}
	}
	doc->save();
}

QString MainWindow::selectFile( const QString &filename, bool fixedExt )
{
	static const QString adoc = tr("Documents (%1)").arg( "*.adoc" );
	static const QString bdoc = tr("Documents (%1)").arg( "*.bdoc" );
	static const QString edoc = tr("Documents (%1)").arg( "*.edoc" );
	static const QString asic = tr("Documents (%1)").arg( "*.asice *.sce" );
	const QString ext = QFileInfo( filename ).suffix().toLower();
	QStringList exts;
	QString active;
	if( fixedExt )
	{
		if( ext == "bdoc" ) exts << bdoc;
		if( ext == "asic" || ext == "sce" ) exts << asic;
		if( ext == "edoc" ) exts << edoc;
		if( ext == "adoc" ) exts << adoc;
	}
	else
	{
		exts << bdoc << asic << edoc << adoc;
		if( ext == "bdoc" ) active = bdoc;
		if( ext == "asice" || ext == "sce" ) active = asic;
		if( ext == "edoc" ) active = edoc;
		if( ext == "adoc" ) active = adoc;
	}

	return FileDialog::getSaveFileName( this, tr("Save file"), filename, exts.join(";;"), &active );
}

void MainWindow::setCurrentPage( Pages page )
{
	int prev = stack->currentIndex();
	stack->setCurrentIndex( page );

	QString file = doc->fileName().normalized( QString::NormalizationForm_C );
	setWindowFilePath( file );
	setWindowTitle( file.isEmpty() ? tr("DigiDoc3 client") : QFileInfo( file ).fileName() );

	switch( page )
	{
	case Sign:
	{
		if( (prev == Home || prev == View) &&
			Settings(qApp->applicationName()).value( "ClientIntro", true ).toBool() )
		{
			prevpage = prev;
			introCheck->setChecked( false );
			setCurrentPage( Intro );
			break;
		}

		signContentView->setColumnHidden( DocumentModel::Remove, !doc->signatures().isEmpty() );
		signContentView->setColumnHidden( DocumentModel::Id, true );
		signAddFile->setVisible( doc->signatures().isEmpty() );
		break;
	}
	case View:
	{
		qDeleteAll( viewSignatures->findChildren<SignatureWidget*>() );

		unsigned int i = 0;
		DigiDocSignature::SignatureStatus status = DigiDocSignature::Valid;
		const QList<DigiDocSignature> signatures = doc->signatures();
		for(const DigiDocSignature &c: signatures)
		{
			SignatureWidget *signature = new SignatureWidget( c, i++, viewSignatures );
			viewSignaturesLayout->insertWidget( 0, signature );
			connect( signature, SIGNAL(removeSignature(unsigned int)),
				SLOT(viewSignaturesRemove(unsigned int)) );
			DigiDocSignature::SignatureStatus next = c.validate();
			if(status < next) status = next;
		}

		for(const DigiDocSignature &c: doc->timestamps())
		{
			SignatureWidget *signature = new SignatureWidget(c, i++, viewSignatures);
			viewSignaturesLayout->insertWidget(viewSignaturesLayout->count(), signature);
			DigiDocSignature::SignatureStatus next = c.validate();
			if(status < next) status = next;
		}

		viewFileName->setToolTip( QDir::toNativeSeparators( doc->fileName().normalized( QString::NormalizationForm_C ) ) );
		viewFileName->setText( QString("<a href=\"%1\">%2</a>").arg( viewFileName->toolTip().toHtmlEscaped() )
			.arg( viewFileName->fontMetrics().elidedText( viewFileName->toolTip(), Qt::ElideMiddle, viewFileName->width() ) ) );
		viewSignaturesLabel->setText( tr( "Signature(s)", "", signatures.size() ) );
		viewFileNameSave->setVisible( doc->isSupported() );

		switch( status )
		{
		case DigiDocSignature::Invalid: viewSignaturesError->setText( tr("NB! Invalid signature") ); break;
		case DigiDocSignature::Unknown: viewSignaturesError->setText( "<i>" + tr("NB! Status unknown") + "</i>" ); break;
		case DigiDocSignature::Test: viewSignaturesError->setText( tr("NB! Test signature") ); break;
		case DigiDocSignature::Warning: viewSignaturesError->setText( "<font color=\"#FFB366\">" + tr("NB! Signature contains warnings") + "</font>" ); break;
		case DigiDocSignature::NonQSCD: viewSignaturesError->clear(); break;
		case DigiDocSignature::Valid: viewSignaturesError->clear(); break;
		}
		break;
	}
	default: break;
	}
}

void MainWindow::showCardStatus()
{
	Application::restoreOverrideCursor();
	TokenData t = qApp->signer()->tokensign();
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
	else if( t.card().isEmpty() && !t.readers().isEmpty() )
	{
		QString text = tr("No card in reader\n\n"
			"Check if the ID-card is inserted correctly to the reader.\n"
			"New ID-cards have chip on the back side of the card.");
		infoCard->setText( text );
		infoCard->setAccessibleDescription( text );
	}
	else
	{
		infoCard->setText( tr("No readers found") );
		infoCard->setAccessibleDescription( tr("No readers found") );
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

void MainWindow::showWarning( const QString &text )
{
	signContentFrame->setEnabled( text.isEmpty() );
	signSignerRole->setEnabled( text.isEmpty() );
	message->move(
		message->parentWidget()->width()/2 - message->width()/2,
		message->parentWidget()->height()/2 - message->height()/2 );
	message->setText( text );
	message->setVisible( !text.isEmpty() );
}

void MainWindow::viewSignaturesRemove( unsigned int num )
{
	doc->removeSignature( num );
	save();
	enableSign();
	setCurrentPage( doc->signatures().isEmpty() ? Sign : View );
}
