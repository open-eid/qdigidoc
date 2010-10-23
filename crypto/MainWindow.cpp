/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009,2010 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009,2010 Raul Metsma <raul@innovaatik.ee>
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

#include "Application.h"
#include "KeyDialog.h"
#include "Poller.h"

#include <common/AboutWidget.h>
#include <common/Common.h>
#include <common/Settings.h>
#include <common/TokenData.h>

#include <QDateTime>
#include <QDesktopServices>
#include <QDragEnterEvent>
#include <QFileDialog>
#include <QMessageBox>
#include <QSslCertificate>
#include <QTextStream>
#include <QUrl>

MainWindow::MainWindow( const QStringList &args )
:	QWidget()
,	cardsGroup( new QActionGroup( this ) )
{
	setAttribute( Qt::WA_DeleteOnClose, true );
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

	QButtonGroup *buttonGroup = new QButtonGroup( this );

	buttonGroup->addButton( settings, HeadSettings );
	buttonGroup->addButton( help, HeadHelp );
	buttonGroup->addButton( about, HeadAbout );

	buttonGroup->addButton( homeCreate, HomeCreate );
	buttonGroup->addButton( homeView, HomeView );

	introNext = introButtons->addButton( tr( "Next" ), QDialogButtonBox::ActionRole );
	buttonGroup->addButton( introNext, IntroNext );
	buttonGroup->addButton( introButtons->button( QDialogButtonBox::Cancel ), IntroBack );

	viewCrypt = viewButtons->addButton( tr("Encrypt"), QDialogButtonBox::ActionRole );
	buttonGroup->addButton( viewCrypt, ViewCrypt );
	buttonGroup->addButton( viewButtons->button( QDialogButtonBox::Close ), ViewClose );
	connect( buttonGroup, SIGNAL(buttonClicked(int)),
		SLOT(buttonClicked(int)) );

	connect( cards, SIGNAL(activated(QString)), qApp->poller(), SLOT(selectCard(QString)), Qt::QueuedConnection );
	connect( qApp, SIGNAL(dataChanged()), SLOT(showCardStatus()) );

	doc = new CryptoDoc( this );
	connect( doc, SIGNAL(error(QString,int,QString)), SLOT(showWarning(QString,int,QString)) );

	connect( viewContentView, SIGNAL(remove(int)),
		SLOT(removeDocument(int)) );
	connect( viewContentView, SIGNAL(save(int,QString)),
		doc, SLOT(saveDocument(int,QString)) );

	cards->hack();
	languages->hack();
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
		Settings().value( "Main/Language", deflang ).toString() ) );
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

	if( !args.isEmpty() )
	{
		params = args;
		buttonClicked( HomeCreate );
	}
}

bool MainWindow::addFile( const QString &file )
{
	if( doc->isNull() )
	{
		Settings s;
		s.beginGroup( "Crypto" );
		QFileInfo info( file );
		QString docname = QString( "%1/%2.cdoc" )
			.arg( s.value( "DefaultDir", info.absolutePath() ).toString() )
			.arg( info.fileName() );

		bool select = s.value( "AskSaveAs", false ).toBool();
		if( !select && QFile::exists( docname ) )
		{
			QMessageBox::StandardButton b = QMessageBox::warning( this, windowTitle(),
				tr( "%1 already exists.<br />Do you want replace it?" ).arg( docname ),
				QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
			select = b == QMessageBox::No;
		}

		if( !Common::canWrite( docname ) )
		{
			select = true;
			qApp->showWarning( tr("You dont have permissions to write file %1").arg( docname ) );
		}

		while( select )
		{
			docname = QFileDialog::getSaveFileName(
				this, tr("Save file"), docname, tr("Documents (*.cdoc)") );
			if( docname.isEmpty() )
				return false;
			if( QFileInfo( docname ).suffix().toLower() != "cdoc" )
				docname.append( ".cdoc" );
			if( !Common::canWrite( docname ) )
				qApp->showWarning( tr("You dont have permissions to write file %1").arg( docname ) );
			else
				select = false;
		}

		if( QFile::exists( docname ) )
			QFile::remove( docname );
		doc->create( docname );
	}

	if( !QFile::exists( file ) )
	{
		qApp->showWarning( tr("File does not exists %1").arg( file ) );
		return false;
	}

	// Check if file exist and ask confirmation to overwrite
	QList<CDocument> docs = doc->documents();
	for( int i = 0; i < docs.size(); ++i )
	{
		if( QFileInfo( docs[i].filename ).fileName() ==
			QFileInfo( file ).fileName() )
		{
			QMessageBox::StandardButton btn = QMessageBox::warning( this,
				windowTitle(), tr("Container contains file with same name, ovewrite?"),
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

	doc->addFile( file, "" );
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
		QDesktopServices::openUrl( QUrl( "http://support.sk.ee/" ) );
		break;
	case HomeView:
	{
		QString file = QFileDialog::getOpenFileName( this, tr("Open container"),
			QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ),
			tr("Documents (*.cdoc *.CDOC)") );
		if( !file.isEmpty() && doc->open( file ) )
			setCurrentPage( View );
		break;
	}
	case HomeCreate:
		if( Settings().value( "Crypto/Intro", true ).toBool() )
		{
			introCheck->setChecked( false );
			introNext->setEnabled( false );
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
				if( doc->isNull() && f.suffix().toLower() == "cdoc" )
				{
					doc->open( f.absoluteFilePath() );
					break;
				}
				else if( !addFile( f.absoluteFilePath() ) )
					break;
			}
			params.clear();
			if( !doc->isNull() )
			{
				setCurrentPage( View );
				break;
			}
		}

		QStringList list = QFileDialog::getOpenFileNames( this, tr("Select documents"),
			QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) );
		if( !list.isEmpty() )
		{
			Q_FOREACH( const QString &file, list )
			{
				if( !addFile( file ) )
					return;
			}
			setCurrentPage( View );
		}
		else if( doc->isNull() )
			setCurrentPage( Home );
		break;
	}
	case IntroBack:
	case ViewClose:
		doc->clear();
		setCurrentPage( Home );
		break;
	case ViewCrypt:
		if( doc->isEncrypted() )
		{
			QLabel *progress = new QLabel( tr("Decrypting"), view );
			progress->setAlignment( Qt::AlignCenter );
			progress->setFixedSize( 300, 20 );
			progress->setStyleSheet( "font: bold; border: 1px solid black; background-color: white;" );
			progress->move( view->geometry().center() - progress->geometry().center() );
			progress->show();
			QApplication::processEvents();

			doc->decrypt();

			progress->deleteLater();

			if( doc->isSigned() )
			{
				QMessageBox::StandardButton b = QMessageBox::warning( this, windowTitle(),
					tr("This container contains signature! Open with QDigiDocClient?"),
					QMessageBox::Yes|QMessageBox::No, QMessageBox::Yes );
				if( b != QMessageBox::Yes )
					break;
				QString file = QString( doc->fileName() ).append( ".ddoc" );
				if( doc->saveDDoc( file ) )
				{
					if( !Common::startDetached( "qdigidocclient", QStringList() << file ) )
						showWarning( tr("Failed to start process '%1'").arg( "qdigidocclient" ), -1 );
				}
			}
		}
		else
		{
			if( doc->encrypt() )
				doc->save();
		}
		setCurrentPage( View );
		break;
	default: break;
	}
}

void MainWindow::changeCard( QAction *a )
{ QMetaObject::invokeMethod( qApp->poller(), "selectCard", Qt::QueuedConnection, Q_ARG(QString,a->data().toString()) ); }
void MainWindow::changeLang( QAction *a ) { on_languages_activated( a->data().toUInt() ); }

void MainWindow::closeDoc() { buttonClicked( ViewClose ); }

void MainWindow::dragEnterEvent( QDragEnterEvent *e )
{
	if( e->mimeData()->hasUrls() && !doc->isEncrypted() )
		e->acceptProposedAction();
}

void MainWindow::dropEvent( QDropEvent *e )
{
	Q_FOREACH( const QUrl &u, e->mimeData()->urls() )
	{
		if( u.scheme() == "file" )
			params << u.toLocalFile();
	}
	buttonClicked( HomeCreate );
}

void MainWindow::on_introCheck_stateChanged( int state )
{
	Settings().setValue( "Crypto/Intro", state == Qt::Unchecked );
	introNext->setEnabled( state == Qt::Checked );
}

void MainWindow::on_languages_activated( int index )
{
	Settings().setValue( "Main/Language", lang[index] );

	switch( index )
	{
	case 1: QLocale::setDefault( QLocale( QLocale::English, QLocale::UnitedKingdom ) ); break;
	case 2: QLocale::setDefault( QLocale( QLocale::Russian, QLocale::RussianFederation ) ); break;
	default: QLocale::setDefault( QLocale( QLocale::Estonian, QLocale::Estonia ) ); break;
	}
	qApp->loadTranslation( lang[index] );
	retranslateUi( this );
	languages->setCurrentIndex( index );
	introNext->setText( tr( "Next" ) );
	showCardStatus();
	updateView();
}

void MainWindow::parseLink( const QString &link )
{
	if( link == "addFile" )
	{
		QStringList list = QFileDialog::getOpenFileNames( this, tr("Select documents"),
			QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) );
		if( list.isEmpty() )
			return;
		Q_FOREACH( const QString &file, list )
			addFile( file );
		setCurrentPage( View );
	}
	else if( link == "addRecipient" )
	{
		if( doc->isEncrypted() )
			return;

		KeyAddDialog *key = new KeyAddDialog( doc, this );
		connect( key, SIGNAL(updateView()), SLOT(updateView()) );
		key->move( pos() );
		key->show();
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
	else if( link == "saveAll" )
	{
		QString dir = QFileDialog::getExistingDirectory( this,
			tr("Select folder where files will be stored"),
			QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) );
		if( dir.isEmpty() )
			return;
		QAbstractItemModel *m = viewContentView->model();
		for( int i = 0; i < m->rowCount(); ++i )
		{
			QString file = QString( "%1/%2" )
				.arg( dir ).arg( m->index( i, 0 ).data().toString() );
			if( QFile::exists( file ) )
			{
				QMessageBox::StandardButton b = QMessageBox::warning( this, windowTitle(),
					tr( "%1 already exists.<br />Do you want replace it?" ).arg( file ),
					QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
				if( b == QMessageBox::No )
				{
					file = QFileDialog::getSaveFileName( this, tr("Save file"), file );
					if( file.isEmpty() )
						continue;
				}
			}
			doc->saveDocument( i, file );
		}
	}
	else if( link == "openUtility" )
	{
		if( !Common::startDetached( "qesteidutil" ) )
			showWarning( tr("Failed to start process '%1'").arg( "qesteidutil" ), -1 );
	}
}

void MainWindow::removeDocument( int index )
{
	doc->removeDocument( index );
	setCurrentPage( View );
}

void MainWindow::removeKey( int id )
{
	doc->removeKey( id );
	setCurrentPage( View );
}

void MainWindow::setCurrentPage( Pages page )
{
	stack->setCurrentIndex( page );

	if( !doc->fileName().isEmpty() )
	{
		setWindowTitle( QString( "%1 - %2" )
			.arg( QFileInfo( doc->fileName() ).fileName() )
			.arg( tr("DigiDoc3 Crypto") ) );
	}
	else
		setWindowTitle( tr("DigiDoc3 Crypto") );

	switch( page )
	{
	case View:
	{
		viewFileName->setText( tr("Container: <b>%1</b>")
			.arg( QDir::toNativeSeparators( doc->fileName() ) ) );

		viewLinks->setVisible( doc->isEncrypted() );
		viewContentLinks->setHidden( doc->isEncrypted() );
		viewKeysLinks->setHidden( doc->isEncrypted() );

		viewContentView->setColumnHidden( 2, doc->isEncrypted() );
		viewContentView->setColumnHidden( 3, doc->isEncrypted() );
		viewContentView->setContent( doc->documents() );

		Q_FOREACH( KeyWidget *w, viewKeys->findChildren<KeyWidget*>() )
			w->deleteLater();

		int j = 0;
		QList<CKey> keys = doc->keys();
		for( QList<CKey>::const_iterator i = keys.constBegin(); i != keys.constEnd(); ++i )
		{
			KeyWidget *key = new KeyWidget( *i, j, doc->isEncrypted(), viewKeys );
			connect( key, SIGNAL(remove(int)), SLOT(removeKey(int)) );
			viewKeysLayout->insertWidget( j++, key );
		}

		viewCrypt->setText( doc->isEncrypted() ? tr("Decrypt") : tr("Encrypt") );
		viewCrypt->setEnabled(
			(!doc->isEncrypted() && viewContentView->model()->rowCount()) ||
			(doc->isEncrypted() && keys.contains( CKey( qApp->tokenData().cert() ) )) );
		break;
	}
	default: break;
	}
}

void MainWindow::showCardStatus()
{
	if( !qApp->tokenData().card().isEmpty() && !qApp->tokenData().cert().isNull() )
		infoCard->setText( Common::tokenInfo( Common::AuthCert, qApp->tokenData() ) );
	else if( !qApp->tokenData().card().isEmpty() )
		infoCard->setText( tr("Loading data") );
	else if( qApp->tokenData().card().isEmpty() )
		infoCard->setText( tr("No card in reader") );

	viewCrypt->setEnabled(
		(!doc->isEncrypted() && viewContentView->model()->rowCount()) ||
		(doc->isEncrypted() &&
		 !(qApp->tokenData().flags() & TokenData::PinLocked) &&
		 doc->keys().contains( CKey( qApp->tokenData().cert() ) )) );

	cards->clear();
	cards->addItems( qApp->tokenData().cards() );
	cards->setVisible( qApp->tokenData().cards().size() > 1 );
	cards->setCurrentIndex( cards->findText( qApp->tokenData().card() ) );
	qDeleteAll( cardsGroup->actions() );
	for( int i = 0; i < qApp->tokenData().cards().size(); ++i )
	{
		QAction *a = cardsGroup->addAction( new QAction( cardsGroup ) );
		a->setData( qApp->tokenData().cards().at( i ) );
		a->setShortcut( Qt::CTRL + (Qt::Key_1 + i) );
		addAction( a );
	}
}

void MainWindow::showWarning( const QString &msg, int err, const QString &errmsg )
{
	QString s( msg );
	switch( err )
	{
	case 60:
		s += "<br />" + tr("Wrong PIN or PIN is blocked");
		break;
	case -1: break;
	default:
		s += "<br />" + tr("Error code: %1").arg( err );
		if( !errmsg.isEmpty() )
			s += QString(" (%1)").arg( errmsg );
	}
	qApp->showWarning( s );
}

void MainWindow::updateView() { setCurrentPage( Pages(stack->currentIndex()) ); }
