/*
 * QDigiDocCrypto
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

#include "KeyDialog.h"

#include <common/CertificateWidget.h>
#include <common/IKValidator.h>
#include <common/SslCertificate.h>
#include "LdapSearch.h"

#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QMessageBox>
#include <QProgressBar>
#include <QRegExpValidator>
#include <QTextStream>

KeyWidget::KeyWidget( const CKey &key, int id, bool encrypted, QWidget *parent )
:	QWidget( parent )
,	m_id( id )
,	m_key( key )
{
	setToolTip( key.recipient );
	QLabel *label = new QLabel( key.recipient, this );
	label->setWordWrap( true );
	label->setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Preferred );

	QString content;
	content += "<a href=\"details\">" + tr("Show details") + "</a>";
	if( !encrypted )
		content += "<br /><a href=\"remove\">" + tr("Remove") + "</a>";
	QLabel *btn = new QLabel( content, this );
	btn->setAlignment( Qt::AlignRight );
	connect( btn, SIGNAL(linkActivated(QString)), SLOT(link(QString)) );

	QVBoxLayout *l = new QVBoxLayout( this );
	l->addWidget( label );
	l->addWidget( btn );
}

void KeyWidget::link( const QString &url )
{
	if( url == "details" )
		(new KeyDialog( m_key, this ))->show();
	else if( url == "remove" )
		Q_EMIT remove( m_id );
}



KeyDialog::KeyDialog( const CKey &key, QWidget *parent )
:	QWidget( parent )
,	k( key )
{
	setupUi( this );
	setAttribute( Qt::WA_DeleteOnClose );
	setWindowFlags( Qt::Dialog );
	buttonBox->addButton( tr("Show certificate"), QDialogButtonBox::AcceptRole );

	title->setText( k.recipient );

	addItem( tr("Key"), k.recipient );
	addItem( tr("Crypt method"), k.type );
	//addItem( tr("ID"), k.id );
	addItem( tr("Expires"), key.cert.expiryDate().toLocalTime().toString("dd.MM.yyyy hh:mm:ss") );
	addItem( tr("Issuer"), key.cert.issuerInfo( QSslCertificate::CommonName ) );
	view->resizeColumnToContents( 0 );
}

void KeyDialog::addItem( const QString &parameter, const QString &value )
{
	QTreeWidgetItem *i = new QTreeWidgetItem( view );
	i->setText( 0, parameter );
	i->setText( 1, value );
	view->addTopLevelItem( i );
}

void KeyDialog::showCertificate()
{ CertificateDialog( k.cert, this ).exec(); }



KeyAddDialog::KeyAddDialog( CryptoDoc *_doc, QWidget *parent )
:	QWidget( parent )
,	doc( _doc )
{
	setupUi( this );
	setAttribute( Qt::WA_DeleteOnClose );
	setWindowFlags( Qt::Dialog );

	cardButton = buttonBox->addButton( tr("Add cert from card"), QDialogButtonBox::ActionRole );
	connect( cardButton, SIGNAL(clicked()), SLOT(addCardCert()) );
	connect( buttonBox->addButton( tr("Add cert from file"), QDialogButtonBox::ActionRole ),
		SIGNAL(clicked()), SLOT(addFile()) );
	connect( doc, SIGNAL(dataChanged()), SLOT(enableCardCert()) );
	enableCardCert();

	skView->header()->setStretchLastSection( false );
	skView->header()->setResizeMode( 0, QHeaderView::Stretch );
	skView->header()->setResizeMode( 1, QHeaderView::ResizeToContents );
	skView->header()->setResizeMode( 2, QHeaderView::ResizeToContents );
	connect( skView, SIGNAL(doubleClicked(QModelIndex)), SLOT(on_add_clicked()) );

	usedView->header()->setStretchLastSection( false );
	usedView->header()->setResizeMode( 0, QHeaderView::Stretch );
	usedView->header()->setResizeMode( 1, QHeaderView::ResizeToContents );
	usedView->header()->setResizeMode( 2, QHeaderView::ResizeToContents );
	loadHistory();

	ldap = new LdapSearch( this );
	connect( ldap, SIGNAL(searchResult(QList<CKey>)), SLOT(showResult(QList<CKey>)) );
	connect( ldap, SIGNAL(error(QString)), SLOT(showError(QString)) );

	validator = new IKValidator( this );
	on_searchType_currentIndexChanged( 0 );
	add->setEnabled( false );
	progress->setVisible( false );
}

void KeyAddDialog::addCardCert()
{ addKeys( QList<CKey>() << CKey( doc->authCert() ) ); }

void KeyAddDialog::addFile()
{
	QString file = QFileDialog::getOpenFileName( this, windowTitle(),
		QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ),
		tr("Certificates (*.pem *.cer *.crt)") );
	if( file.isEmpty() )
		return;

	QFile f( file );
	if( !f.open( QIODevice::ReadOnly ) )
	{
		QMessageBox::warning( this, windowTitle(), tr("Failed to open certifiacte") );
		return;
	}

	CKey k( QSslCertificate( &f, QSsl::Pem ) );
	if( k.cert.isNull() )
	{
		f.reset();
		k.setCert( QSslCertificate( &f, QSsl::Der ) );
	}
	if( k.cert.isNull() )
	{
		QMessageBox::warning( this, windowTitle(), tr("Failed to read certificate") );
	}
	else if( !SslCertificate( k.cert ).keyUsage().contains( SslCertificate::DataEncipherment ) )
	{
		QMessageBox::warning( this, windowTitle(), tr("This certificate is not usable for crypting") );
	}
	else
		addKeys( QList<CKey>() << k );

	f.close();
}

void KeyAddDialog::addKeys( const QList<CKey> &keys )
{
	if( keys.isEmpty() )
		return;
	bool status = true;
	Q_FOREACH( const CKey &key, keys )
	{
		if( key.cert.expiryDate() <= QDateTime::currentDateTime() &&
			QMessageBox::No == QMessageBox::warning( this, windowTitle(),
				tr("Are you sure that you want use certificate for encrypting, which expired on %1?<br />"
					"When decrypter has updated certificates then decrypting is impossible.")
					.arg( key.cert.expiryDate().toString( "dd.MM.yyyy hh:mm:ss" ) ),
				QMessageBox::Yes|QMessageBox::No, QMessageBox::No ) )
			return;
		status = qMin( status, doc->addKey( key ) );
	}
	Q_EMIT updateView();
	keyAddStatus->setText( status ? tr("Keys added successfully") : tr("Failed to add keys") );
}

void KeyAddDialog::enableCardCert() { cardButton->setDisabled( doc->authCert().isNull() ); }

void KeyAddDialog::disableSearch( bool disable )
{
	progress->setVisible( disable );
	search->setDisabled( disable );
	skView->setDisabled( disable );
	searchType->setDisabled( disable );
	searchContent->setDisabled( disable );
}

void KeyAddDialog::loadHistory()
{
	QFile f( QString( "%1/certhistory.txt" )
		.arg( QDesktopServices::storageLocation( QDesktopServices::DataLocation ) ) );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	QTextStream s( &f );
	while( true )
	{
		QString line = s.readLine();
		if( line.isEmpty() )
			break;
		QStringList list = line.split( ';' );

		QTreeWidgetItem *i = new QTreeWidgetItem( usedView );
		i->setText( 0, list.value( 0 ) );
		i->setText( 1, list.value( 1 ) );
		i->setText( 2, list.value( 2 ) );
		i->setData( 0, Qt::UserRole, list.value( 3 ).toInt() );
		usedView->addTopLevelItem( i );
	}
	f.close();
}

void KeyAddDialog::on_add_clicked()
{
	if( !skView->selectionModel()->hasSelection() )
		return;

	QList<CKey> keys;
	Q_FOREACH( const QModelIndex &index, skView->selectionModel()->selectedRows() )
	{
		const CKey k = skKeys.value( index.row() );
		keys << skKeys.value( index.row() );
		if( usedView->findItems( k.recipient, Qt::MatchExactly ).isEmpty() )
		{
			QTreeWidgetItem *i = new QTreeWidgetItem( usedView );
			i->setText( 0, k.recipient );
			i->setText( 1, k.cert.issuerInfo( "CN" ) );
			i->setText( 2, k.cert.expiryDate().toLocalTime().toString( "dd.MM.yyyy" ) );
			i->setData( 0, Qt::UserRole, SslCertificate( k.cert ).isTempel() );
			usedView->addTopLevelItem( i );
		}
	}
	addKeys( keys );

	saveHistory();
}

void KeyAddDialog::on_remove_clicked()
{
	qDeleteAll( usedView->selectedItems() );
	saveHistory();
}

void KeyAddDialog::on_search_clicked()
{
	if( searchType->currentIndex() == 0 &&
		!IKValidator::isValid( searchContent->text() ) )
	{
		QMessageBox::warning( this, windowTitle(),
			tr("Social security number is not valid!") );
	}
	else
	{
		skView->clear();
		add->setEnabled( false );
		disableSearch( true );
		if( searchType->currentIndex() == 0 )
			ldap->search( QString( "(serialNumber=%1)" ).arg( searchContent->text() ) );
		else
			ldap->search( QString( "(cn=*%1*)" ).arg( searchContent->text() ) );
	}
}

void KeyAddDialog::on_searchType_currentIndexChanged( int index )
{
	if( index == 0 )
		searchContent->setValidator( validator );
	else
		searchContent->setValidator( 0 );
	skView->clear();
	searchContent->clear();
	searchContent->setFocus();
}

void KeyAddDialog::on_usedView_itemDoubleClicked( QTreeWidgetItem *item, int )
{
	searchType->setCurrentIndex( item->data( 0, Qt::UserRole ).toInt() );
	if( searchType->currentIndex() == 0 )
		searchContent->setText( item->text( 0 ).split( ',' ).value( 2 ) );
	else
		searchContent->setText( item->text( 0 ) );
	tabWidget->setCurrentIndex( 0 );
	on_search_clicked();
}

void KeyAddDialog::saveHistory()
{
	QString path = QDesktopServices::storageLocation( QDesktopServices::DataLocation );
	QDir().mkpath( path );
	QFile f( path.append( "/certhistory.txt" ) );
	if( !f.open( QIODevice::WriteOnly|QIODevice::Truncate ) )
		return;

	QTextStream s( &f );
	for( int i = 0; i < usedView->topLevelItemCount(); ++i )
	{
		QTreeWidgetItem *item = usedView->topLevelItem( i );
		s << item->text( 0 ) << ';';
		s << item->text( 1 ) << ';';
		s << item->text( 2 ) << ';';
		s << item->data( 0, Qt::UserRole ).toInt() << '\n';
	}
	f.close();
}

void KeyAddDialog::showError( const QString &msg )
{
	disableSearch( false );
	QMessageBox::warning( this, windowTitle(), msg );
}

void KeyAddDialog::showResult( const QList<CKey> &result )
{
	skKeys.clear();

	Q_FOREACH( const CKey &k, result )
	{
		if( !SslCertificate( k.cert ).keyUsage().contains( SslCertificate::DataEncipherment ) )
			continue;

		skKeys << k;
		QTreeWidgetItem *i = new QTreeWidgetItem( skView );
		i->setText( 0, k.recipient );
		i->setText( 1, k.cert.issuerInfo( QSslCertificate::CommonName ) );
		i->setText( 2, k.cert.expiryDate().toLocalTime().toString( "dd.MM.yyyy" ) );
		i->setData( 0, Qt::UserRole, SslCertificate( k.cert ).isTempel() );
		skView->addTopLevelItem( i );
	}

	disableSearch( false );
	add->setEnabled( true );

	if( !skKeys.isEmpty() )
	{
		skView->setCurrentIndex( skView->model()->index( 0, 0 ) );
		add->setFocus();
	}
	else
		showError( tr("Empty result") );
}
