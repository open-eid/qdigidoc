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

#pragma once

#include "ui_MobileDialog.h"

#include <QHash>
#include <QNetworkRequest>
#include <QSslError>

class DigiDoc;
class QDomElement;
class QNetworkAccessManager;
class QNetworkReply;
class QTimeLine;

class MobileDialog : public QDialog, private Ui::MobileDialog
{
	Q_OBJECT

public:
	MobileDialog( DigiDoc *doc, QWidget *parent = 0 );
	void setSignatureInfo( const QString &city, const QString &state, const QString &zip,
							const QString &country, const QString &role, const QString &role2 );
	void sign( const QString &ssid, const QString &cell );
	QString fName;

private Q_SLOTS:
	void endProgress();
	void finished( QNetworkReply *reply );
	void sendStatusRequest( int frame );
	void sslErrors( QNetworkReply *reply, const QList<QSslError> &errors );

private:
	bool getFiles();
	QString escapeChars( const QString &in ) const;
	QString elementText( const QDomElement &element, const QString &tag ) const;
	QString insertBody( const QString &action, const QString &body ) const;
	void startSession();

	DigiDoc *m_doc;
	QTimeLine *statusTimer;
	QNetworkAccessManager *manager;
	QNetworkRequest request;
	QString signature, files;

	int sessionCode;
	QHash< QByteArray, QString > mobileResults;
};
