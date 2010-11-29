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

#pragma once

#include "ui_KeyAddDialog.h"
#include "ui_KeyDialog.h"

#include "CryptoDoc.h"

class CryptoDoc;
class IKValidator;
class LdapSearch;

class KeyWidget: public QWidget
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
		DigiID = 2,
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
	QList<QStringList> m_data;
};

class KeyModel: public QAbstractTableModel
{
	Q_OBJECT

public:
	KeyModel( QObject *parent = 0 );

	int columnCount( const QModelIndex &index = QModelIndex() ) const;
	QVariant headerData( int section, Qt::Orientation orientation, int role = Qt::DisplayRole ) const;
	QVariant data( const QModelIndex &index, int role = Qt::DisplayRole ) const;
	int rowCount( const QModelIndex &index = QModelIndex() ) const;

	void clear();
	CKey key( const QModelIndex &index ) const;
	void load( const QList<CKey> &result );

private:
	QList<CKey> skKeys;
};

class KeyAddDialog: public QWidget, private Ui::KeyAddDialog
{
	Q_OBJECT

public:
	KeyAddDialog( CryptoDoc *doc, QWidget *parent = 0 );

Q_SIGNALS:
	void updateView();

private Q_SLOTS:
	void addCardCert();
	void addFile();
	void addKeys( const QList<CKey> &keys );
	void enableCardCert();
	void on_add_clicked();
	void on_remove_clicked();
	void on_search_clicked();
	void on_searchType_currentIndexChanged( int index );
	void on_usedView_doubleClicked( const QModelIndex &index );
	void showError( const QString &msg );
	void showResult( const QList<CKey> &result );

private:
	void disableSearch( bool disable );

	QPushButton *cardButton;
	CryptoDoc	*doc;
	IKValidator *validator;
	KeyModel	*keyModel;
	LdapSearch	*ldap;
};
