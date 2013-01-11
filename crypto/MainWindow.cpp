/*
 * QDigiDocCrypto
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

#include "Application.h"
#include "KeyDialog.h"
#include "Poller.h"

#include <common/FileDialog.h>
#include <common/Settings.h>
#include <common/TokenData.h>

#include <QtCore/QTextStream>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#include <QtGui/QDragEnterEvent>
#include <QtGui/QMessageBox>
#include <QtGui/QProgressBar>
#include <QtGui/QProgressDialog>

MainWindow::MainWindow( QWidget *parent )
:	QWidget( parent )
,	cardsGroup( new QActionGroup( this ) )
{
	setAttribute( Qt::WA_DeleteOnClose, true );
#ifdef TESTING
	if( !qApp->arguments().contains( "-crash" ) )
#endif
	setupUi( this );
	setFixedSize( geometry().size() );
	Common::setAccessibleName( introContent );

	cards->hide();

	// Buttons
	buttonGroup = new QButtonGroup( this );

	buttonGroup->addButton( settings, HeadSettings );
	buttonGroup->addButton( help, HeadHelp );
	buttonGroup->addButton( about, HeadAbout );

	buttonGroup->addButton( homeCreate, HomeCreate );
	buttonGroup->addButton( homeView, HomeView );

	buttonGroup->addButton( viewEmail, ViewEmail );
	buttonGroup->addButton( viewBrowse, ViewBrowse );
	buttonGroup->addButton( viewFileNameSave, ViewSave );
	buttonGroup->addButton( viewSaveAll, ViewSaveAll );
	buttonGroup->addButton( viewAddFile, ViewAddFile );
	buttonGroup->addButton( viewKeysLinks, ViewAddKey );

	buttonGroup->addButton(
		introButtons->addButton( tr( "I agree" ), QDialogButtonBox::AcceptRole ), IntroAgree );
	buttonGroup->addButton( introButtons->button( QDialogButtonBox::Cancel ), IntroBack );

	buttonGroup->addButton(
		viewButtons->addButton( tr("Encrypt"), QDialogButtonBox::AcceptRole ), ViewCrypto );
	buttonGroup->addButton( viewButtons->button( QDialogButtonBox::Close ), ViewClose );
	connect( buttonGroup, SIGNAL(buttonClicked(int)),
		SLOT(buttonClicked(int)) );

	connect( cards, SIGNAL(activated(QString)), qApp->poller(), SLOT(selectCard(QString)), Qt::QueuedConnection );
	connect( qApp->poller(), SIGNAL(dataChanged()), SLOT(showCardStatus()) );

	// Cryptodoc
	doc = new CryptoDoc( this );

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

	viewContentView->setDocumentModel( doc->documents() );
	connect( doc->documents(), SIGNAL(rowsInserted(QModelIndex,int,int)), SLOT(updateView()) );
	connect( doc->documents(), SIGNAL(rowsRemoved(QModelIndex,int,int)), SLOT(updateView()) );
	connect( doc->documents(), SIGNAL(modelReset()), SLOT(updateView()) );
}

bool MainWindow::addFile( const QString &file )
{
	QFileInfo fileinfo( file );
	if( doc->isNull() )
	{
		Settings s;
		s.beginGroup( "Crypto" );
		QString docname = QString( "%1/%2.cdoc" )
			.arg( s.value( "DefaultDir", fileinfo.absolutePath() ).toString() )
			.arg( fileinfo.suffix() == "cdoc" ? fileinfo.fileName() : fileinfo.completeBaseName() );

		bool select = s.value( "AskSaveAs", true ).toBool();
		if( !select && QFile::exists( docname ) )
		{
			QMessageBox::StandardButton b = QMessageBox::warning( this, tr("DigiDoc3 crypto"),
				tr( "%1 already exists.<br />Do you want replace it?" ).arg( docname ),
				QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
			select = b == QMessageBox::No;
		}

#ifndef APPSTORE
		if( !FileDialog::fileIsWritable( docname ) )
		{
			select = true;
			qApp->showWarning(
				tr( "You don't have sufficient privileges to write this file into folder %1" ).arg( docname ) );
		}
#endif

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
	for( int i = 0; i < doc->documents()->rowCount(); ++i )
	{
		QModelIndex index = doc->documents()->index( i, CDocumentModel::Name );
		if( index.data().toString() == fileinfo.fileName() )
		{
			QMessageBox::StandardButton btn = QMessageBox::warning( this,
				tr("File already in container"),
				tr("%1\nalready in container, ovewrite?").arg( display ),
				QMessageBox::Yes | QMessageBox::No, QMessageBox::No );
			if( btn == QMessageBox::Yes )
			{
				doc->documents()->removeRow( index.row() );
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
		QDesktopServices::openUrl( QUrl( Common::helpUrl() ) );
		break;
	case HomeView:
	{
		QString file = FileDialog::getOpenFileName( this, tr("Open container"), QString(),
			tr("Documents (%1)").arg( "*.cdoc") );
		if( !file.isEmpty() && doc->open( file ) )
			setCurrentPage( View );
		break;
	}
	case HomeCreate:
		if( Settings().value( "Crypto/Intro", true ).toBool() )
		{
			introCheck->setChecked( false );
			buttonGroup->button( IntroAgree )->setEnabled( false );
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
				setCurrentPage( View );
		}
		else
		{
			QStringList list = FileDialog::getOpenFileNames( this, tr("Select documents") );
			Q_FOREACH( const QString &file, list )
			{
				if( !addFile( file ) )
					return;
			}
			setCurrentPage( doc->isNull() ? Home : View );
		}
		break;
	}
	case IntroBack:
	case ViewClose:
		doc->clear();
		if( quitOnClose )
			close();
		setCurrentPage( Home );
		break;
	case ViewCrypto:
	{
		QProgressDialog p( this );
		p.setWindowFlags( (p.windowFlags() | Qt::CustomizeWindowHint) & ~Qt::WindowCloseButtonHint );
		if( QProgressBar *bar = p.findChild<QProgressBar*>() )
			bar->setTextVisible( false );
		p.setCancelButton( 0 );
		p.setRange( 0, 0 );
		p.open();

		if( doc->isEncrypted() )
		{
			p.setLabelText( tr("Decrypting") );
			doc->decrypt();

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
						qApp->showWarning( tr("Failed to start process '%1'").arg( "qdigidocclient" ) );
				}
			}
		}
		else
		{
			p.setLabelText( tr("Encrypting") );
			if( doc->encrypt() )
				save();
		}
		setCurrentPage( View );
		break;
	}
	case ViewAddFile:
	{
		QStringList list = FileDialog::getOpenFileNames( this, tr("Select documents") );
		if( list.isEmpty() )
			return;
		Q_FOREACH( const QString &file, list )
			addFile( file );
		setCurrentPage( View );
		break;
	}
	case ViewAddKey:
	{
		if( doc->isEncrypted() )
			return;

		CertAddDialog *key = new CertAddDialog( doc, this );
		connect( key, SIGNAL(updateView()), SLOT(updateView()) );
		key->move( pos() );
		key->show();
		break;
	}
	case ViewBrowse:
	{
		QUrl url = QUrl::fromLocalFile( doc->fileName() );
		url.setScheme( "browse" );
		QDesktopServices::openUrl( url );
		break;
	}
	case ViewEmail:
	{
		QUrl url;
		url.setScheme( "mailto" );
		url.addQueryItem( "subject", QFileInfo( doc->fileName() ).fileName() );
		url.addQueryItem( "attachment", QFileInfo( doc->fileName() ).absoluteFilePath() );
		QDesktopServices::openUrl( url );
		break;
	}
	case ViewSave:
	{
		QString file = selectFile( doc->fileName() );
		if( !file.isEmpty() )
			doc->save( file );
		setCurrentPage( View );
		break;
	}
	case ViewSaveAll:
	{
		QString dir = FileDialog::getExistingDirectory( this,
			tr("Select folder where files will be stored") );
		if( dir.isEmpty() )
			return;
		if( !FileDialog::folderIsWritable( dir ) )
		{
			qApp->showWarning(
				tr( "You don't have sufficient privileges to write this file into folder %1" ).arg( dir ) );
			return;
		}
		CDocumentModel *m = doc->documents();
		for( int i = 0; i < m->rowCount(); ++i )
		{
			QModelIndex index = m->index( i, CDocumentModel::Name );
			QString source = index.data( Qt::UserRole ).toString();
			QString dest = m->mkpath( index, dir );
			if( source == dest )
				continue;
			if( QFile::exists( dest ) )
			{
				QMessageBox::StandardButton b = QMessageBox::warning( this, windowTitle(),
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
		break;
	}
	default: break;
	}
}

void MainWindow::changeCard( QAction *a )
{ QMetaObject::invokeMethod( qApp->poller(), "selectCard", Qt::QueuedConnection, Q_ARG(QString,a->data().toString()) ); }
void MainWindow::changeLang( QAction *a ) { qApp->loadTranslation( a->data().toString() ); }

void MainWindow::closeDoc() { buttonClicked( ViewClose ); }

bool MainWindow::event( QEvent *e )
{
	switch( e->type() )
	{
	case QEvent::DragEnter:
	{
		QDragEnterEvent *d = static_cast<QDragEnterEvent*>( e );
		if( d->mimeData()->hasUrls() )
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
		buttonClicked( HomeCreate );
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

bool MainWindow::isOpen() const { return !doc->isNull(); }

void MainWindow::on_introCheck_stateChanged( int state )
{
	Settings().setValue( "Crypto/Intro", state == Qt::Unchecked );
	buttonGroup->button( IntroAgree )->setEnabled( state == Qt::Checked );
}

void MainWindow::on_languages_activated( int index )
{ qApp->loadTranslation( lang[index] ); }

void MainWindow::open( const QStringList &_params )
{
	quitOnClose = true;
	params = _params;
	buttonClicked( HomeCreate );
}

void MainWindow::parseLink( const QString &link )
{
	if( link == "openUtility" )
	{
		if( !Common::startDetached( "qesteidutil" ) )
			qApp->showWarning( tr("Failed to start process '%1'").arg( "qesteidutil" ) );
	}
}

void MainWindow::removeKey( int id )
{
	doc->removeKey( id );
	setCurrentPage( View );
}

void MainWindow::retranslate()
{
	retranslateUi( this );
	languages->setCurrentIndex( lang.indexOf( Settings::language() ) );
	buttonGroup->button( IntroAgree )->setText( tr("I agree") );
	showCardStatus();
	updateView();
}

void MainWindow::save()
{
	if( !FileDialog::fileIsWritable( doc->fileName() ) &&
		QMessageBox::Yes == QMessageBox::warning( this, tr("DigiDoc3 crypto"),
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
		file = FileDialog::getSaveFileName( this, tr("Save file"), file,
			tr("Documents (%1)").arg( "*.cdoc") );
		if( file.isEmpty() )
			return QString();
		if( QFileInfo( file ).suffix().toLower() != "cdoc" )
			file.append( ".cdoc" );
		if( !FileDialog::fileIsWritable( file ) )
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
			.arg( tr("DigiDoc3 Crypto") ) );
	}
	else
		setWindowTitle( tr("DigiDoc3 Crypto") );

	switch( page )
	{
	case View:
	{
		viewFileName->setToolTip( QDir::toNativeSeparators( doc->fileName() ) );
		viewFileName->setText( viewFileName->fontMetrics().elidedText(
			viewFileName->toolTip(), Qt::ElideMiddle, viewFileName->width() ) );

		viewBrowse->setVisible( doc->isEncrypted() );
		viewEmail->setVisible( doc->isEncrypted() );
		viewAddFile->setHidden( doc->isEncrypted() );
		viewSaveAll->setHidden( doc->isEncrypted() );
		viewKeysLinks->setHidden( doc->isEncrypted() );

		viewContentView->setColumnHidden( CDocumentModel::Save, doc->isEncrypted() );
		viewContentView->setColumnHidden( CDocumentModel::Remove, doc->isEncrypted() );

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

		buttonGroup->button( ViewCrypto )->setText( doc->isEncrypted() ? tr("Decrypt") : tr("Encrypt") );
		buttonGroup->button( ViewCrypto )->setEnabled(
			(!doc->isEncrypted() && viewContentView->model()->rowCount()) ||
			(doc->isEncrypted() && keys.contains( CKey( qApp->poller()->token().cert() ) )) );
		break;
	}
	default: break;
	}
}

void MainWindow::showCardStatus()
{
	Application::restoreOverrideCursor();
	TokenData t = qApp->poller()->token();
	if( !t.card().isEmpty() && !t.cert().isNull() )
	{
		infoFrame->setText( t.toHtml() );
		infoFrame->setAccessibleDescription( t.toAccessible() );
	}
	else if( !t.card().isEmpty() )
	{
		infoFrame->setText( tr("Loading data") );
		infoFrame->setAccessibleDescription( tr("Loading data") );
		Application::setOverrideCursor( Qt::BusyCursor );
	}
	else if( t.card().isEmpty() && !t.readers().isEmpty() )
	{
		QString text = tr("No card in reader\n\n"
			"Check if the ID-card is inserted correctly to the reader.\n"
			"New ID-cards have chip on the back side of the card.");
		infoFrame->setText( text );
		infoFrame->setAccessibleDescription( text );
	}
	else
	{
		infoFrame->setText( tr("No readers found") );
		infoFrame->setAccessibleDescription( tr("No readers found") );
	}

	buttonGroup->button( ViewCrypto )->setEnabled(
		(!doc->isEncrypted() && doc->documents()->rowCount()) ||
		(doc->isEncrypted() &&
		 !(t.flags() & TokenData::PinLocked) &&
		 doc->keys().contains( CKey( t.cert() ) )) );

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
}

void MainWindow::updateView() { setCurrentPage( Pages(stack->currentIndex()) ); }
