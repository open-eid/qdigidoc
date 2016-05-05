/*
 * QDigiDocCrypto
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

#include "client/Application.h"
#include "client/QSigner.h"
#include "KeyDialog.h"

#include <client/FileDialog.h>
#include <common/Settings.h>
#include <common/TokenData.h>

#include <QtCore/QMimeData>
#include <QtCore/QProcess>
#include <QtCore/QTextStream>
#include <QtCore/QUrl>
#include <QtCore/QUrlQuery>
#include <QtGui/QDesktopServices>
#include <QtGui/QDragEnterEvent>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QProgressDialog>

using namespace Crypto;

MainWindow::MainWindow( QWidget *parent )
:	QWidget( parent )
,	cardsGroup( new QActionGroup( this ) )
,	quitOnClose( false )
{
	setAttribute( Qt::WA_DeleteOnClose, true );
#ifdef TESTING
	if( !qApp->arguments().contains( "-crash" ) )
#endif
	setupUi( this );
	setFixedSize( geometry().size() );
	Common::setAccessibleName( introContent );

#if defined(Q_OS_WIN) || defined(Q_OS_MAC)
	QString background = qApp->applicationDirPath() + "/qdigidoccrypto.png";
#else
	QString background = DATADIR "/qdigidoc/qdigidoccrypto.png";
#endif
	if(QFile::exists(background))
	{
		label->setPixmap(QPixmap());
		setStyleSheet(QString("#background { background-image: url(\"%1\"); }").arg(background));
		style()->unpolish(this);
		style()->polish(this);
	}

	cards->hide();

	// Buttons
	buttonGroup = new QButtonGroup( this );

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
	connect( buttonGroup, SIGNAL(buttonClicked(int)), SLOT(buttonClicked(int)) );
	connect( viewFileName, SIGNAL(linkActivated(QString)), this, SLOT(messageClicked(QString)) );

	connect( cards, SIGNAL(activated(QString)), qApp->signer(), SLOT(selectAuthCard(QString)), Qt::QueuedConnection );
	connect( qApp->signer(), SIGNAL(authDataChanged(TokenData)), SLOT(showCardStatus()) );

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
		s.beginGroup( "Client" );
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
			docname = selectFile( docname );
			if( docname.isEmpty() )
				return false;
		}

		if( QFile::exists( docname ) )
			QFile::remove( docname );
		doc->clear( docname );
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

	doc->documents()->addFile( file );
	return true;
}

void MainWindow::buttonClicked( int button )
{
	switch( button )
	{
	case HeadAbout:
		qApp->showAbout();
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

		if( doc->isEncrypted() )
		{
			p.setLabelText( tr("Decrypting") );
			p.open();
			doc->decrypt();

			if( doc->isSigned() )
			{
				QMessageBox::StandardButton b = QMessageBox::warning( this, windowTitle(),
					tr("This container contains signature! Open with QDigiDocClient?"),
					QMessageBox::Yes|QMessageBox::No, QMessageBox::Yes );
				if( b != QMessageBox::Yes )
					break;
				QString file = QString( QFileInfo( doc->fileName() ).baseName() ).append( ".ddoc" );
				file = FileDialog::getSaveFileName( this, tr("Save file"), file, tr("Documents (%1)").arg("*.DDoc") );
				if( !file.isEmpty() && doc->saveDDoc( file ) )
					qApp->showClient( QStringList() << file );
			}
		}
		else
		{
			if( doc->keys().isEmpty() )
			{
				qApp->showWarning( tr("No keys specified") );
				break;
			}
			p.setLabelText( tr("Encrypting") );
			p.open();
			if( !FileDialog::fileIsWritable( doc->fileName() ) &&
				QMessageBox::Yes == QMessageBox::warning( this, tr("DigiDoc3 crypto"),
					tr("Cannot alter container %1. Save different location?")
						.arg( doc->fileName().normalized( QString::NormalizationForm_C ) ),
					QMessageBox::Yes|QMessageBox::No, QMessageBox::Yes ) )
			{
				QString file = selectFile( doc->fileName() );
				if( !file.isEmpty() )
				{
					doc->encrypt( file );
					return;
				}
			}
			doc->encrypt();
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
		QUrlQuery q;
		q.addQueryItem("subject", QFileInfo(doc->fileName()).fileName());
		q.addQueryItem("attachment", QFileInfo(doc->fileName()).absoluteFilePath());
		QUrl url;
		url.setScheme("mailto");
		url.setQuery(q);
		QDesktopServices::openUrl( url );
		break;
	}
	case ViewSave:
	{
		QString file = selectFile( doc->fileName() );
		if( !file.isEmpty() )
		{
			if( !doc->isEncrypted() )
				qApp->showWarning( CryptoDoc::tr("Container is not encrypted") );
			else
				QFile::copy( doc->fileName(), file );
		}
		setCurrentPage( View );
		break;
	}
	case ViewSaveAll:
	{
		QString dir = FileDialog::getExistingDirectory( this,
			tr("Select folder where files will be stored") );
		if( dir.isEmpty() )
			return;
		CDocumentModel *m = doc->documents();
		for( int i = 0; i < m->rowCount(); ++i )
		{
			QModelIndex index = m->index( i, CDocumentModel::Name );
			QString dest = dir + "/" + index.data(Qt::UserRole).toString();
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
			m->copy( index, dest );
		}
		break;
	}
	default: break;
	}
}

void MainWindow::changeCard( QAction *a )
{ QMetaObject::invokeMethod( qApp->signer(), "selectAuthCard", Qt::QueuedConnection, Q_ARG(QString,a->data().toString()) ); }
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

void MainWindow::messageClicked( const QString &link )
{
	if( link == viewFileName->toolTip() )
		buttonClicked( ViewBrowse );
}

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
#ifdef Q_OS_MAC
		if( !QProcess::startDetached( "/usr/bin/open", QStringList() << "-a" << "qesteidutil" ) )
#else
		if( !QProcess::startDetached( "qesteidutil" ) )
#endif
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
	version->setText( windowTitle() + " " + qApp->applicationVersion() );
	showCardStatus();
	updateView();
}

QString MainWindow::selectFile( const QString &filename )
{
	return FileDialog::getSaveFileName( this, tr("Save file"), filename,
		tr("Documents (%1)").arg( "*.cdoc") );
}

void MainWindow::setCurrentPage( Pages page )
{
	stack->setCurrentIndex( page );

	QString file = doc->fileName().normalized( QString::NormalizationForm_C );
	setWindowFilePath( file );
	setWindowTitle( file.isEmpty() ? tr("DigiDoc3 Crypto") : QFileInfo( file ).fileName() );

	switch( page )
	{
	case View:
	{
		viewFileName->setToolTip( QDir::toNativeSeparators( doc->fileName() ) );
		if( doc->isEncrypted() )
			viewFileName->setText( QString("<a href=\"%1\">%2</a>").arg( viewFileName->toolTip().toHtmlEscaped() )
				.arg( viewFileName->fontMetrics().elidedText( viewFileName->toolTip(), Qt::ElideMiddle, viewFileName->width() ) ) );
		else
			viewFileName->setText(
				viewFileName->fontMetrics().elidedText( viewFileName->toolTip(), Qt::ElideMiddle, viewFileName->width() ) );

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
			(doc->isEncrypted() && keys.contains( CKey( qApp->signer()->tokenauth().cert() ) )) );
		break;
	}
	default: break;
	}
}

void MainWindow::showCardStatus()
{
	Application::restoreOverrideCursor();
	TokenData t = qApp->signer()->tokenauth();
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
#ifndef INTERNATIONAL
		QString text = tr("No card in reader\n\n"
			"Check if the ID-card is inserted correctly to the reader.\n"
			"New ID-cards have chip on the back side of the card.");
#else
		QString text = tr("No card in reader\n\n"
			"Check if the ID-card is inserted correctly to the reader.");
#endif
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
