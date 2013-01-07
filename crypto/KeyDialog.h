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

#pragma once

#include "ui_CertAddDialog.h"
#include "ui_KeyDialog.h"

#include "CryptoDoc.h"

class IKValidator;
class LdapSearch;

class KeyWidget: public QLabel
{
	Q_OBJECT

public:
	KeyWidget( const CKey &key, int id, bool encrypted, QWidget *parent = 0 );

Q_SIGNALS:
	void remove( int id );

private Q_SLOTS:
	void link( const QString &url );

private:
	int m_id;
	CKey m_key;
};

class KeyDialog: public QWidget, private Ui::KeyDialog
{
	Q_OBJECT

public:
	KeyDialog( const CKey &key, QWidget *parent = 0 );

private Q_SLOTS:
	void showCertificate();

private:
	void addItem( const QString &parameter, const QString &value );

	CKey k;
};

class HistoryModel: public QAbstractTableModel
{
	Q_OBJECT

public:
	enum KeyType
	{
		IDCard = 0,
		TEMPEL = 1,
		DigiID = 2
	};

	enum {
		Owner,
		Type,
		Issuer,
		Expire,

		NColumns
	};

	HistoryModel( QObject *parent = 0 );

	int columnCount( const QModelIndex &parent = QModelIndex() ) const;
	QVariant headerData( int section, Qt::Orientation orientation, int role ) const;
	bool insertRows( int row, int count, const QModelIndex &parent = QModelIndex() );
	QVariant data( const QModelIndex &index, int role = Qt::DisplayRole ) const;
	bool removeRows( int row, int count, const QModelIndex &parent = QModelIndex() );
	int rowCount( const QModelIndex &parent = QModelIndex() ) const;
	bool setData( const QModelIndex &index, const QVariant &value, int role = Qt::EditRole );

public Q_SLOTS:
	bool submit();

private:
	QString path() const;
	QList<QStringList> m_data;
};

class CertModel: public QAbstractTableModel
{
	Q_OBJECT

public:
	enum {
		Owner = 0,
		Issuer,
		Expire,

		NColumns
	};
	CertModel( QObject *parent = 0 );

	int columnCount( const QModelIndex &index = QModelIndex() ) const;
	QVariant headerData( int section, Qt::Orientation orientation, int role = Qt::DisplayRole ) const;
	QVariant data( const QModelIndex &index, int role = Qt::DisplayRole ) const;
	int rowCount( const QModelIndex &index = QModelIndex() ) const;

	void clear();
	void load( const QList<QSslCertificate> &result );

private:
	QList<QSslCertificate> certs;
};

class CertAddDialog: public QWidget, private Ui::CertAddDialog
{
	Q_OBJECT

public:
	CertAddDialog( CryptoDoc *doc, QWidget *parent = 0 );

Q_SIGNALS:
	void updateView();

private Q_SLOTS:
	void addCardCert();
	void addCerts( const QList<QSslCertificate> &certs );
	void addFile();
	void enableCardCert();
	void on_add_clicked();
	void on_remove_clicked();
	void on_search_clicked();
	void on_searchType_currentIndexChanged( int index );
	void on_usedView_doubleClicked( const QModelIndex &index );
	void showError( const QString &msg );
	void showResult( const QList<QSslCertificate> &result );

private:
	void disableSearch( bool disable );

	QPushButton *cardButton;
	CryptoDoc	*doc;
	IKValidator *validator;
	CertModel	*certModel;
	LdapSearch	*ldap;
};
