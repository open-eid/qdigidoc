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

#include <QThread>

class PollerPrivate;
class TokenData;

class Poller: public QThread
{
	Q_OBJECT

public:
	enum ErrorCode
	{
		NullCode = 0,
		PinOk,
		PinCanceled,
		PinIncorrect,
		PinLocked,
		PinUnknown,
	};

	Poller( QObject *parent = 0 );
	~Poller();

	bool decrypt( const QByteArray &in, QByteArray &out );
	ErrorCode errorCode() const;
	TokenData token() const;

Q_SIGNALS:
	void dataChanged( const TokenData &data );
	void error( const QString &msg, quint8 error = 0 );

private Q_SLOTS:
	void selectCard( const QString &card );

private:
	void run();

	PollerPrivate *d;
};
