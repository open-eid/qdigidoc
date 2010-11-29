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

#include "KeyDialog.h"

#include "Application.h"
#include "LdapSearch.h"
#include "Poller.h"

#include <common/CertificateWidget.h>
#include <common/Common.h>
#include <common/IKValidator.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QMessageBox>
#include <QProgressBar>
#include <QRegExpValidator>
#include <QTimer>
#include <QXmlStreamReader>
#include <QXmlStreamWriter>

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
		(new KeyDialog( m_key, qApp->activeWindow() ))->show();
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



HistoryModel::HistoryModel( QObject *parent )
:	QAbstractTableModel( parent )
{
	QFile f( QString( "%1/certhistory.xml" )
		.arg( QDesktopServices::storageLocation( QDesktopServices::DataLocation ) ) );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	QXmlStreamReader xml;
	xml.setDevice( &f );

	if( !xml.readNextStartElement() || xml.name() != "History" )
		return;

	while( xml.readNextStartElement() )
	{
		if( xml.name() == "item" )
		{
			m_data << (QStringList()
				<< xml.attributes().value( "CN" ).toString()
				<< xml.attributes().value( "type" ).toString()
				<< xml.attributes().value( "issuer" ).toString()
				<< xml.attributes().value( "expireDate" ).toString());
		}
		xml.skipCurrentElement();
	}
}

int HistoryModel::columnCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : 4; }

QVariant HistoryModel::headerData( int section, Qt::Orientation orientation, int role ) const
{
	if( role != Qt::DisplayRole || orientation == Qt::Vertical )
		return QVariant();
	switch( section )
	{
	case 0: return tr("Owner");
	case 1: return tr("Type");
	case 2: return tr("Issuer");
	case 3: return tr("Expiry date");
	default: return QVariant();
	}
}

bool HistoryModel::insertRows( int row, int count, const QModelIndex &parent )
{
	beginInsertRows( parent, row, row + count );
	for( int i = 0; i < count; ++i )
		m_data.insert( row + i, QStringList() << "" << "" << "" << "" );
	endInsertRows();
	return true;
}

QVariant HistoryModel::data( const QModelIndex &index, int role ) const
{
	if( !index.isValid() || index.row() >= m_data.size() )
		return QVariant();

	QStringList row = m_data[index.row()];
	switch( role )
	{
	case Qt::DisplayRole:
		if( index.column() != 1 )
			return row.value( index.column() );
		switch( row.value( 1 ).toInt() )
		{
		case DigiID: return tr("DIGI-ID");
		case Tempel: return tr("TEMPEL");
		default: return tr("ID-CARD");
		}
	case Qt::EditRole: return row.value( index.column() );
	default: return QVariant();
	}
}

bool HistoryModel::removeRows( int row, int count, const QModelIndex &parent )
{
	beginRemoveRows( parent, row, row + count );
	for( int i = row + count - 1; i >= row; --i )
		m_data.removeAt( i );
	endInsertRows();
	return true;
}

int HistoryModel::rowCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : m_data.size(); }

bool HistoryModel::setData( const QModelIndex &index, const QVariant &value, int role )
{
	if( !index.isValid() || index.row() >= m_data.size() )
		return false;
	switch( role )
	{
	case Qt::EditRole:
		m_data[index.row()][index.column()] = value.toString();
		Q_EMIT dataChanged( index, index );
		return true;
	default: return false;
	}
}

bool HistoryModel::submit()
{
	QString path = QDesktopServices::storageLocation( QDesktopServices::DataLocation );
	QDir().mkpath( path );
	QFile f( path.append( "/certhistory.xml" ) );
	if( !f.open( QIODevice::WriteOnly|QIODevice::Truncate ) )
		return false;

	QXmlStreamWriter xml;
	xml.setDevice( &f );
	xml.setAutoFormatting( true );
	xml.writeStartDocument();
	xml.writeStartElement( "History" );
	Q_FOREACH( const QStringList &item, m_data )
	{
		xml.writeStartElement( "item" );
		xml.writeAttribute( "CN", item.value(0) );
		xml.writeAttribute( "type", item.value(1) );
		xml.writeAttribute( "issuer", item.value(2) );
		xml.writeAttribute( "expireDate", item.value(3) );
		xml.writeEndElement();
	}
	xml.writeEndDocument();

	return true;
}



KeyModel::KeyModel( QObject *parent )
:	QAbstractTableModel( parent )
{}

void KeyModel::clear()
{ skKeys.clear(); reset(); }

int KeyModel::columnCount( const QModelIndex &index ) const
{ return index.isValid() ? 0 : 3; }

QVariant KeyModel::headerData( int section, Qt::Orientation orientation, int role ) const
{
	if( role != Qt::DisplayRole || orientation == Qt::Vertical )
		return QVariant();
	switch( section )
	{
	case 0: return tr("Owner");
	case 1: return tr("Issuer");
	case 2: return tr("Expiry date");
	default: return QVariant();
	}
}

QVariant KeyModel::data( const QModelIndex &index, int role ) const
{
	if( !index.isValid() || index.row() >= skKeys.size() )
		return QVariant();

	CKey k = skKeys[index.row()];
	switch( role )
	{
	case Qt::DisplayRole:
		switch( index.column() )
		{
		case 0: return k.recipient;
		case 1: return k.cert.issuerInfo( QSslCertificate::CommonName );
		case 2: return k.cert.expiryDate().toLocalTime().toString( "dd.MM.yyyy" );
		default: break;
		}
	default: break;
	}
	return QVariant();
}

CKey KeyModel::key(const QModelIndex &index) const
{ return skKeys.value( index.row() ); }

void KeyModel::load( const QList<CKey> &result )
{
	skKeys.clear();
	Q_FOREACH( const CKey &k, result )
		if( SslCertificate( k.cert ).keyUsage().contains( SslCertificate::DataEncipherment ) )
			skKeys << k;
	reset();
}

int KeyModel::rowCount( const QModelIndex &index ) const
{ return index.isValid() ? 0 : skKeys.count(); }



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
	connect( qApp->poller(), SIGNAL(dataChanged(TokenData)), SLOT(enableCardCert()) );
	enableCardCert();

	skView->setModel( keyModel = new KeyModel( this ) );
	skView->header()->setStretchLastSection( false );
	skView->header()->setResizeMode( 0, QHeaderView::Stretch );
	skView->header()->setResizeMode( 1, QHeaderView::ResizeToContents );
	skView->header()->setResizeMode( 2, QHeaderView::ResizeToContents );
	connect( skView, SIGNAL(doubleClicked(QModelIndex)), SLOT(on_add_clicked()) );

	usedView->setModel( new HistoryModel( this ) );
	usedView->header()->setStretchLastSection( false );
	usedView->header()->setResizeMode( 0, QHeaderView::Stretch );
	usedView->header()->setResizeMode( 1, QHeaderView::ResizeToContents );
	usedView->header()->setResizeMode( 2, QHeaderView::ResizeToContents );

	ldap = new LdapSearch( this );
	connect( ldap, SIGNAL(searchResult(QList<CKey>)), SLOT(showResult(QList<CKey>)) );
	connect( ldap, SIGNAL(error(QString)), SLOT(showError(QString)) );

	validator = new IKValidator( this );
	on_searchType_currentIndexChanged( 0 );
	add->setEnabled( false );
	progress->setVisible( false );
}

void KeyAddDialog::addCardCert()
{ addKeys( QList<CKey>() << CKey( qApp->tokenData().cert() ) ); }

void KeyAddDialog::addFile()
{
	QString file = Common::normalized( QFileDialog::getOpenFileName( this, windowTitle(),
		QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ),
		tr("Certificates (*.pem *.cer *.crt)") ) );
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
	QTimer::singleShot( 3*1000, keyAddStatus, SLOT(hide()) );
}

void KeyAddDialog::enableCardCert() { cardButton->setDisabled( qApp->tokenData().cert().isNull() ); }

void KeyAddDialog::disableSearch( bool disable )
{
	progress->setVisible( disable );
	search->setDisabled( disable );
	skView->setDisabled( disable );
	searchType->setDisabled( disable );
	searchContent->setDisabled( disable );
}

void KeyAddDialog::on_add_clicked()
{
	if( !skView->selectionModel()->hasSelection() )
		return;

	QAbstractItemModel *m = usedView->model();
	QList<CKey> keys;
	Q_FOREACH( const QModelIndex &index, skView->selectionModel()->selectedRows() )
	{
		const CKey k = keyModel->key( index );
		keys << k;
		if( !m->match( m->index( 0, 0 ), Qt::DisplayRole, k.recipient, 1, Qt::MatchExactly ).isEmpty() )
			continue;

		SslCertificate cert( k.cert );
		int row = m->rowCount();
		m->insertRow( row );
		m->setData( m->index( row, 0 ), cert.subjectInfo( "CN" ) );
		switch( cert.type() )
		{
		case SslCertificate::TempelType: m->setData( m->index( row, 1 ), HistoryModel::Tempel ); break;
		case SslCertificate::DigiIDTestType:
		case SslCertificate::DigiIDType: m->setData( m->index( row, 1 ), HistoryModel::DigiID ); break;
		default: m->setData( m->index( row, 1 ), HistoryModel::IDCard ); break;
		}
		m->setData( m->index( row, 2 ), cert.issuerInfo( "CN" ) );
		m->setData( m->index( row, 3 ), cert.expiryDate().toLocalTime().toString( "dd.MM.yyyy" ) );
	}
	addKeys( keys );
	usedView->model()->submit();
}

void KeyAddDialog::on_remove_clicked()
{
	QList<int> rows;
	Q_FOREACH( const QModelIndex &i, usedView->selectionModel()->selectedRows() )
		rows << i.row();
	qSort( rows );
	for( int i = rows.size() - 1; i >= 0; --i )
		usedView->model()->removeRow( rows[i] );
	usedView->model()->submit();
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
		keyModel->clear();
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
	keyModel->clear();
	searchContent->clear();
	searchContent->setFocus();
}

void KeyAddDialog::on_usedView_doubleClicked( const QModelIndex &index )
{
	QAbstractItemModel *m = usedView->model();
	QString text = m->index( index.row(), 0 ).data().toString();
	tabWidget->setCurrentIndex( 0 );
	searchType->setCurrentIndex(
		m->index( index.row(), 1 ).data( Qt::EditRole ).toInt() == HistoryModel::Tempel );
	searchContent->setText( searchType->currentIndex() == 0 ? text.split( ',' ).value( 2 ) : text );
	on_search_clicked();
}

void KeyAddDialog::showError( const QString &msg )
{
	disableSearch( false );
	QMessageBox::warning( this, windowTitle(), msg );
}

void KeyAddDialog::showResult( const QList<CKey> &result )
{
	keyModel->load( result );

	disableSearch( false );
	add->setEnabled( true );

	if( keyModel->rowCount() )
	{
		skView->setCurrentIndex( skView->model()->index( 0, 0 ) );
		if( searchType->currentIndex() == 0 )
			skView->selectAll();
		add->setFocus();
	}
	else
		showError( tr("Empty result") );
}
